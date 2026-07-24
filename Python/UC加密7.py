#!/usr/bin/env python3
"""
Unicode 范围加密工具 (版本 7) - 整体压缩+流式加密，GUI简洁无压缩选项
"""

import os
import zlib
import hashlib
import hmac
import argparse
import sys
import tempfile
from getpass import getpass

BASE = 112
START = 0x0300
MAGIC = b'UC07'
SALT_LEN = 16
NONCE_LEN = 12
SIG_LEN = 32
KEY_LEN = 32
PBKDF2_ITER = 600000
BLOCK_SIZE = 32
CHUNK_SIZE = 64 * 1024

class EncryptorError(Exception):
    pass

def to_chars(data: bytes) -> str:
    return ''.join(chr(START + (b // BASE)) + chr(START + (b % BASE)) for b in data)

def from_chars(s: str) -> bytes:
    if len(s) % 2:
        raise EncryptorError("编码字符串长度必须为偶数")
    res = bytearray()
    for i in range(0, len(s), 2):
        c1 = ord(s[i]) - START
        c2 = ord(s[i+1]) - START
        if not (0 <= c1 < BASE and 0 <= c2 < BASE):
            raise EncryptorError(f"非法字符: U+{ord(s[i]):04X}")
        res.append(c1 * BASE + c2)
    return bytes(res)

class StreamEncoder:
    def __init__(self, fileobj):
        self.file = fileobj
    def feed(self, data: bytes):
        for b in data:
            self.file.write(chr(START + (b // BASE)))
            self.file.write(chr(START + (b % BASE)))
    def flush(self):
        pass

class StreamDecoder:
    def __init__(self):
        self.buf = []
    def feed(self, chars: str) -> bytes:
        self.buf.extend([c for c in chars if START <= ord(c) < START + BASE])
        res = bytearray()
        while len(self.buf) >= 2:
            c1 = ord(self.buf[0]) - START
            c2 = ord(self.buf[1]) - START
            res.append(c1 * BASE + c2)
            self.buf = self.buf[2:]
        return bytes(res)
    def flush(self) -> bytes:
        if self.buf:
            raise EncryptorError("不完整的字符对")
        return b''

class Encryptor:
    def __init__(self, password: str):
        self.password = password.encode('utf-8')

    def _derive_keys(self, salt: bytes):
        km = hashlib.pbkdf2_hmac('sha256', self.password, salt, PBKDF2_ITER, dklen=KEY_LEN)
        return km[:16], km[16:]

    def _keystream(self, key: bytes, nonce: bytes, counter: int, length: int) -> bytes:
        ks = bytearray()
        while len(ks) < length:
            ctr = counter.to_bytes(4, 'big')
            ks.extend(hmac.new(key, nonce + ctr, hashlib.sha256).digest())
            counter += 1
        return bytes(ks[:length])

    def encrypt_stream(self, input_path: str, output_path: str):
        # 1. 流式压缩到临时文件
        with tempfile.NamedTemporaryFile(delete=False) as tmp_comp:
            comp_path = tmp_comp.name
            compressor = zlib.compressobj()
            with open(input_path, 'rb') as fin:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    comp_data = compressor.compress(chunk)
                    if comp_data:
                        tmp_comp.write(comp_data)
                comp_data = compressor.flush()
                if comp_data:
                    tmp_comp.write(comp_data)
            tmp_comp.flush()

        # 2. 加密压缩数据（流式）
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        enc_key, mac_key = self._derive_keys(salt)
        flag = b'\x01'  # 固定压缩

        with tempfile.NamedTemporaryFile(delete=False) as tmp_enc:
            enc_path = tmp_enc.name
            tmp_enc.write(MAGIC + flag + salt + nonce + bytes(SIG_LEN))
            h = hmac.new(mac_key, digestmod=hashlib.sha256)
            counter = 0
            with open(comp_path, 'rb') as fcomp:
                while True:
                    comp_chunk = fcomp.read(CHUNK_SIZE)
                    if not comp_chunk:
                        break
                    ks = self._keystream(enc_key, nonce, counter, len(comp_chunk))
                    encrypted = bytes(a ^ b for a, b in zip(comp_chunk, ks))
                    tmp_enc.write(encrypted)
                    h.update(encrypted)
                    counter += (len(comp_chunk) + BLOCK_SIZE - 1) // BLOCK_SIZE
            signature = h.digest()
            tmp_enc.seek(len(MAGIC) + 1 + SALT_LEN + NONCE_LEN)
            tmp_enc.write(signature)
            tmp_enc.flush()

            # 3. 编码为文本
            with open(enc_path, 'rb') as fbin, open(output_path, 'w', encoding='utf-8') as fout:
                encoder = StreamEncoder(fout)
                while True:
                    data = fbin.read(CHUNK_SIZE)
                    if not data:
                        break
                    encoder.feed(data)
                encoder.flush()

        os.remove(comp_path)
        os.remove(enc_path)

    def decrypt_stream(self, input_path: str, output_path: str, ignore_magic: bool = False):
        # 1. 解码文本为二进制加密包
        with tempfile.NamedTemporaryFile(delete=False) as tmp_enc:
            enc_path = tmp_enc.name
            with open(input_path, 'r', encoding='utf-8') as fin:
                decoder = StreamDecoder()
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    data = decoder.feed(chunk)
                    if data:
                        tmp_enc.write(data)
                remaining = decoder.flush()
                if remaining:
                    tmp_enc.write(remaining)
            tmp_enc.flush()

            # 2. 解析头部并解密
            with open(enc_path, 'rb') as fbin:
                header = fbin.read(len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + SIG_LEN)
                if len(header) < len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + SIG_LEN:
                    raise EncryptorError("文件过短")
                magic = header[:4]
                flag = header[4:5]
                salt = header[5:5+SALT_LEN]
                nonce = header[5+SALT_LEN:5+SALT_LEN+NONCE_LEN]
                signature = header[5+SALT_LEN+NONCE_LEN:5+SALT_LEN+NONCE_LEN+SIG_LEN]

                if not ignore_magic and magic != MAGIC:
                    raise EncryptorError("魔术头不匹配")
                if flag != b'\x01':
                    raise EncryptorError("不支持的压缩标志")

                enc_key, mac_key = self._derive_keys(salt)

                # 验证签名并解密到临时压缩文件
                with tempfile.NamedTemporaryFile(delete=False) as tmp_comp:
                    comp_path = tmp_comp.name
                    h = hmac.new(mac_key, digestmod=hashlib.sha256)
                    counter = 0
                    while True:
                        cipher_chunk = fbin.read(CHUNK_SIZE)
                        if not cipher_chunk:
                            break
                        h.update(cipher_chunk)
                        ks = self._keystream(enc_key, nonce, counter, len(cipher_chunk))
                        plain_comp = bytes(a ^ b for a, b in zip(cipher_chunk, ks))
                        tmp_comp.write(plain_comp)
                        counter += (len(cipher_chunk) + BLOCK_SIZE - 1) // BLOCK_SIZE

                    if not ignore_magic:
                        expected_sig = h.digest()
                        if not hmac.compare_digest(signature, expected_sig):
                            os.remove(comp_path)
                            raise EncryptorError("签名验证失败")
                    tmp_comp.flush()

                    # 3. 解压到最终输出
                    with open(comp_path, 'rb') as fcomp, open(output_path, 'wb') as fout:
                        decompressor = zlib.decompressobj()
                        while True:
                            comp_chunk = fcomp.read(CHUNK_SIZE)
                            if not comp_chunk:
                                break
                            plain = decompressor.decompress(comp_chunk)
                            if plain:
                                fout.write(plain)
                        plain = decompressor.flush()
                        if plain:
                            fout.write(plain)

                    os.remove(comp_path)

        os.remove(enc_path)

def encrypt_file(input_path, output_path, password):
    Encryptor(password).encrypt_stream(input_path, output_path)

def decrypt_file(input_path, output_path, password, ignore_magic=False):
    Encryptor(password).decrypt_stream(input_path, output_path, ignore_magic)

# ==================== 图形界面 (v7.1风格，无压缩选项) ====================
def gui_main():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("错误：无法导入 tkinter，请确保 Python 安装了 Tk 支持。")
        sys.exit(1)

    class EncryptorGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("Unicode 加密工具 v7.5")
            self.root.resizable(False, False)

            self.mode = tk.StringVar(value="encrypt")
            self.input_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.password = tk.StringVar()

            self.create_widgets()

        def create_widgets(self):
            # 模式选择
            mode_frame = ttk.LabelFrame(self.root, text="操作模式", padding=5)
            mode_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
            ttk.Radiobutton(mode_frame, text="加密", variable=self.mode, value="encrypt",
                            command=self.update_mode).grid(row=0, column=0, padx=5)
            ttk.Radiobutton(mode_frame, text="解密", variable=self.mode, value="decrypt",
                            command=self.update_mode).grid(row=0, column=1, padx=5)

            # 输入文件
            ttk.Label(self.root, text="输入文件:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
            ttk.Entry(self.root, textvariable=self.input_path, width=50).grid(row=1, column=1, padx=5, pady=5)
            ttk.Button(self.root, text="浏览...", command=self.browse_input).grid(row=1, column=2, padx=5, pady=5)

            # 输出文件
            ttk.Label(self.root, text="输出文件:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
            ttk.Entry(self.root, textvariable=self.output_path, width=50).grid(row=2, column=1, padx=5, pady=5)
            ttk.Button(self.root, text="浏览...", command=self.browse_output).grid(row=2, column=2, padx=5, pady=5)

            # 密码
            ttk.Label(self.root, text="密码:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
            ttk.Entry(self.root, textvariable=self.password, width=50, show="*").grid(row=3, column=1, padx=5, pady=5)

            # 执行按钮
            self.run_button = ttk.Button(self.root, text="执行", command=self.run)
            self.run_button.grid(row=4, column=1, padx=5, pady=10)

            # 状态栏
            self.status = ttk.Label(self.root, text="就绪", relief="sunken", anchor="w")
            self.status.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

            self.update_mode()

        def update_mode(self):
            # 无压缩选项，仅根据模式更新建议文件名即可
            self.suggest_output()

        def browse_input(self):
            filename = filedialog.askopenfilename(title="选择输入文件")
            if filename:
                self.input_path.set(filename)
                self.suggest_output()

        def browse_output(self):
            filename = filedialog.asksaveasfilename(title="选择输出文件")
            if filename:
                self.output_path.set(filename)

        def suggest_output(self):
            inpath = self.input_path.get()
            if not inpath:
                return
            dirname = os.path.dirname(inpath)
            basename = os.path.basename(inpath)
            if self.mode.get() == "encrypt":
                outname = basename + "-enc"
            else:
                if basename.endswith("-enc"):
                    outname = basename[:-4] + "-dec"
                else:
                    outname = basename + "-dec"
            self.output_path.set(os.path.join(dirname, outname))

        def run(self):
            if not self.input_path.get():
                messagebox.showerror("错误", "请选择输入文件")
                return
            if not self.output_path.get():
                messagebox.showerror("错误", "请指定输出文件")
                return
            if not self.password.get():
                messagebox.showerror("错误", "请输入密码")
                return
            if not os.path.isfile(self.input_path.get()):
                messagebox.showerror("错误", "输入文件不存在")
                return

            try:
                self.status.config(text="正在处理...")
                self.root.update()

                if self.mode.get() == "encrypt":
                    encrypt_file(self.input_path.get(), self.output_path.get(),
                                 self.password.get())
                    msg = f"加密完成！\n输出文件：{self.output_path.get()}"
                else:
                    try:
                        decrypt_file(self.input_path.get(), self.output_path.get(),
                                     self.password.get())
                        msg = f"解密完成！\n输出文件：{self.output_path.get()}"
                    except EncryptorError as e:
                        if "魔术头不匹配" in str(e):
                            answer = messagebox.askyesno(
                                "魔术头不匹配",
                                "文件的魔术头不匹配，可能是旧版本文件。\n是否尝试忽略魔术头并继续？"
                            )
                            if answer:
                                decrypt_file(self.input_path.get(), self.output_path.get(),
                                             self.password.get(), ignore_magic=True)
                                msg = f"解密完成！\n输出文件：{self.output_path.get()}"
                            else:
                                raise
                        else:
                            raise

                self.status.config(text="完成")
                messagebox.showinfo("成功", msg)
            except Exception as e:
                self.status.config(text="错误")
                messagebox.showerror("错误", str(e))

    root = tk.Tk()
    app = EncryptorGUI(root)
    root.mainloop()

# ==================== 命令行接口 ====================
def cli_main():
    parser = argparse.ArgumentParser(description="Unicode加密工具 v7.5")
    parser.add_argument('--gui', action='store_true', help="启动图形界面")
    parser.add_argument('mode', nargs='?', choices=['encrypt', 'decrypt'], help="操作模式")
    parser.add_argument('input', nargs='?', help="输入文件路径")
    parser.add_argument('-o', '--output', help="输出文件路径（默认自动生成）")
    parser.add_argument('-p', '--password', help="密码（若不提供则交互输入）")
    parser.add_argument('--ignore-magic', action='store_true', help="忽略魔术头校验（用于解密旧版本文件）")
    args = parser.parse_args()

    if args.gui or (args.mode is None and args.input is None):
        gui_main()
        return

    if args.mode is None or args.input is None:
        parser.error("命令行模式需要指定 mode 和 input")

    if not os.path.isfile(args.input):
        print(f"错误：文件 {args.input} 不存在")
        return

    password = args.password if args.password else getpass("请输入密码: ")

    if args.output:
        output_path = args.output
    else:
        dir_name = os.path.dirname(args.input)
        base_name = os.path.basename(args.input)
        if args.mode == 'encrypt':
            output_name = base_name + "-enc"
        else:
            if base_name.endswith("-enc"):
                output_name = base_name[:-4] + "-dec"
            else:
                output_name = base_name + "-dec"
        output_path = os.path.join(dir_name, output_name)

    try:
        if args.mode == 'encrypt':
            encrypt_file(args.input, output_path, password)
            print(f"加密完成，输出文件: {output_path}")
        else:
            decrypt_file(args.input, output_path, password, ignore_magic=args.ignore_magic)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")

if __name__ == "__main__":
    cli_main()