#!/usr/bin/env python3
"""
Unicode 加密工具 v10（修正版）
功能：将任意文件进行压缩、身份验证加密后，编码为 Unicode 字符存储；
      支持两种模式：
      - zc : Base-112 编码到可见字符区 (U+0300~U+036F)，膨胀率  4X～5X（高熵文件）
      - zh : 汉字编码到 CJK 基本区 (U+4E00~U+4EFF)，膨胀率 1.5X～3X（高熵文件）
加密流程：压缩 → AES‑CTR 等价流加密（HMAC‑SHA256 作为密钥流）→ HMAC 签名 → 编码 → 存储。
修正：密钥流计数器按实际 HMAC 块数累加，保证与 C 版本互操作。
"""

import os
import zlib
import hashlib
import hmac
import argparse
import sys
import tempfile
from getpass import getpass

# ******************** 常量和协议定义 ********************
MAGIC = b'EN10'            # 文件魔术头
SALT_LEN = 16              # 盐值长度（字节）
NONCE_LEN = 12             # 随机数长度（字节）
SIG_LEN = 32               # HMAC 签名长度（字节）
KEY_LEN = 48               # 派生密钥总长度（加密密钥16 + HMAC密钥32）
PBKDF2_ITER = 600_000      # PBKDF2 迭代次数
CHUNK_SIZE = 65536         # 读写块大小

# 编码模式常量
MODE_ZC = b'zc'            # Base-112 编码（可见字符区）
MODE_ZH = b'zh'            # 汉字编码（CJK 基本区）

# zc 模式参数（Base-112，可见字符区 U+0300 ~ U+036F）
ZC_BASE = 112
ZC_START = 0x0300

# zh 模式参数（汉字编码，CJK 统一表意文字区 U+4E00 ~ U+4EFF）
ZH_BASE = 256
ZH_START = 0x4E00

class EncryptorError(Exception):
    """加密/解密过程中的自定义异常。"""
    pass


# ******************** 编码/解码器 ********************

# ----- zc 模式（Base-112）优化版 -----
def to_zc_chars(data: bytes) -> str:
    result = []
    for byte in data:
        high = byte // ZC_BASE
        low = byte % ZC_BASE
        result.append(chr(ZC_START + high))
        result.append(chr(ZC_START + low))
    return ''.join(result)

def from_zc_chars(s: str) -> bytes:
    """批量解码 zc 字符串，预分配内存，速度更快。"""
    if len(s) % 2 != 0:
        raise EncryptorError('zc 编码字符串长度必须为偶数')
    result = bytearray(len(s) // 2)
    start = ZC_START
    base = ZC_BASE
    for i in range(0, len(s), 2):
        high = ord(s[i]) - start
        low = ord(s[i+1]) - start
        if not (0 <= high < base and 0 <= low < base):
            raise EncryptorError(f"zc 模式非法字符: U+{ord(s[i]):04X}")
        result[i//2] = high * base + low
    return bytes(result)

class ZcStreamEncoder:
    def __init__(self, text_file):
        self.file = text_file
    def feed(self, data: bytes):
        for byte in data:
            high = ZC_START + byte // ZC_BASE
            low = ZC_START + byte % ZC_BASE
            self.file.write(chr(high))
            self.file.write(chr(low))
    def flush(self):
        pass

class ZcStreamDecoder:
    """优化版：批量处理，减少循环和缓冲区操作。"""
    def __init__(self):
        self.remainder = None   # 存储落单的高位字符

    def feed(self, chars: str) -> bytes:
        # 合并上次剩余的字符
        if self.remainder is not None:
            chars = self.remainder + chars
            self.remainder = None

        # 确保偶数长度，保留奇数长度的最后一个字符
        if len(chars) % 2 != 0:
            self.remainder = chars[-1]
            chars = chars[:-1]

        # 批量解码
        result = bytearray()
        start = ZC_START
        base = ZC_BASE
        for i in range(0, len(chars), 2):
            high = ord(chars[i]) - start
            low = ord(chars[i+1]) - start
            if not (0 <= high < base and 0 <= low < base):
                raise EncryptorError(f"zc 模式非法字符: U+{ord(chars[i]):04X}")
            result.append(high * base + low)
        return bytes(result)

    def flush(self) -> bytes:
        if self.remainder is not None:
            raise EncryptorError('zc 模式不完整的字符对')
        return b''

# ----- zh 模式（汉字编码）-----
def to_zh_chars(data: bytes) -> str:
    result = []
    for byte in data:
        result.append(chr(ZH_START + byte))
    return ''.join(result)

def from_zh_chars(s: str) -> bytes:
    result = bytearray(len(s))
    start = ZH_START
    for i, ch in enumerate(s):
        code = ord(ch)
        if not start <= code < start + ZH_BASE:
            raise EncryptorError(f"zh 模式非法字符: U+{code:04X}")
        result[i] = code - start
    return bytes(result)

class ZhStreamEncoder:
    def __init__(self, text_file):
        self.file = text_file
    def feed(self, data: bytes):
        for byte in data:
            self.file.write(chr(ZH_START + byte))
    def flush(self):
        pass

class ZhStreamDecoder:
    def __init__(self):
        pass
    def feed(self, chars: str) -> bytes:
        return from_zh_chars(chars)
    def flush(self) -> bytes:
        return b''


# ******************** 加密/解密核心 ********************
class Encryptor:
    def __init__(self, password: str = None):
        if password is not None:
            self.password = password.encode('utf-8')
        else:
            self.password = None

    @staticmethod
    def _derive_keys(password_bytes: bytes, salt: bytes):
        key_material = hashlib.pbkdf2_hmac(
            'sha256', password_bytes, salt, PBKDF2_ITER, dklen=KEY_LEN
        )
        return key_material[:16], key_material[16:]

    @staticmethod
    def _keystream(cipher_key: bytes, nonce: bytes, counter: int, length: int) -> bytes:
        key_stream = bytearray()
        current_counter = counter
        while len(key_stream) < length:
            counter_bytes = current_counter.to_bytes(4, 'big')
            key_stream.extend(
                hmac.new(cipher_key, nonce + counter_bytes, hashlib.sha256).digest()
            )
            current_counter += 1
        return bytes(key_stream[:length])

    def encrypt_stream(self, input_path: str, output_path: str, mode: str = 'zh'):
        """
        加密文件，支持模式: 'zc' 或 'zh'（默认 zh）
        """
        if mode not in ('zc', 'zh'):
            raise EncryptorError(f'不支持的加密模式: {mode}')
        mode_flag = MODE_ZC if mode == 'zc' else MODE_ZH

        # 1. 压缩
        with tempfile.NamedTemporaryFile(delete=False) as compressed_temp:
            compressed_path = compressed_temp.name
            compressor = zlib.compressobj()
            with open(input_path, 'rb') as fin:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    compressed_chunk = compressor.compress(chunk)
                    if compressed_chunk:
                        compressed_temp.write(compressed_chunk)
                remaining = compressor.flush()
                if remaining:
                    compressed_temp.write(remaining)

        # 2. 生成盐和 nonce
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        cipher_key, mac_key = self._derive_keys(self.password, salt)

        # 3. 构建头部并初始化 HMAC
        header_prefix = MAGIC + mode_flag + salt + nonce
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        mac.update(header_prefix)

        # 4. 加密压缩数据
        with tempfile.NamedTemporaryFile(delete=False) as cipher_temp:
            cipher_path = cipher_temp.name
            cipher_temp.write(header_prefix + bytes(SIG_LEN))

            block_counter = 0
            with open(compressed_path, 'rb') as comp_file:
                while True:
                    plain_block = comp_file.read(CHUNK_SIZE)
                    if not plain_block:
                        break
                    keystream = self._keystream(cipher_key, nonce, block_counter, len(plain_block))
                    encrypted_block = bytes(p ^ k for p, k in zip(plain_block, keystream))
                    cipher_temp.write(encrypted_block)
                    mac.update(encrypted_block)
                    # 修正：按实际 HMAC 块数（每块 32 字节）递增计数器
                    block_counter += (len(plain_block) + 31) // 32

            signature = mac.digest()
            cipher_temp.seek(len(header_prefix))
            cipher_temp.write(signature)
            cipher_temp.flush()

        # 5. 编码为 Unicode 并写入输出文件
        with open(cipher_path, 'rb') as cipher_file, \
             open(output_path, 'w', encoding='utf-8') as out_file:
            if mode == 'zc':
                encoder = ZcStreamEncoder(out_file)
            else:
                encoder = ZhStreamEncoder(out_file)
            while True:
                chunk = cipher_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                encoder.feed(chunk)
            encoder.flush()

        # 清理临时文件
        os.remove(compressed_path)
        os.remove(cipher_path)

    def decrypt_stream(self, input_path: str, output_path: str, ignore_magic: bool = False, user_password: str = None):
        # 1. 读取整个文件内容（不再处理后门）
        with open(input_path, 'r', encoding='utf-8') as fin:
            full_content = fin.read()
        clean_content = full_content  # 直接使用全部内容

        # 2. 根据第一个字符的码点范围判断编码模式
        if not clean_content:
            raise EncryptorError('文件内容为空')
        first_char = clean_content[0]
        code = ord(first_char)
        if ZC_START <= code < ZC_START + ZC_BASE:
            decoder = ZcStreamDecoder()
            mode = 'zc'
        elif ZH_START <= code < ZH_START + ZH_BASE:
            decoder = ZhStreamDecoder()
            mode = 'zh'
        else:
            raise EncryptorError(f'无法识别的编码模式，首字符 U+{code:04X}')

        # 3. 解码为二进制密文
        with tempfile.NamedTemporaryFile(delete=False) as decoded_temp:
            decoded_path = decoded_temp.name
            chunk_size = 65536
            for i in range(0, len(clean_content), chunk_size):
                chunk = clean_content[i:i+chunk_size]
                binary_chunk = decoder.feed(chunk)
                if binary_chunk:
                    decoded_temp.write(binary_chunk)
            remaining = decoder.flush()
            if remaining:
                decoded_temp.write(remaining)
            decoded_temp.flush()

        # 4. 解析头部
        with open(decoded_path, 'rb') as cipher_file:
            header_size = len(MAGIC) + 2 + SALT_LEN + NONCE_LEN + SIG_LEN
            header_data = cipher_file.read(header_size)
            if len(header_data) < header_size:
                raise EncryptorError('文件过短，无法读取完整头部')

            magic = header_data[:4]
            mode_flag = header_data[4:6]
            salt = header_data[6:6+SALT_LEN]
            nonce = header_data[6+SALT_LEN:6+SALT_LEN+NONCE_LEN]
            stored_signature = header_data[6+SALT_LEN+NONCE_LEN:6+SALT_LEN+NONCE_LEN+SIG_LEN]

            if not ignore_magic and magic != MAGIC:
                raise EncryptorError('魔术头不匹配 (文件可能被篡改或非本工具加密)')

            # 检查模式标志，仅允许 zc 和 zh
            if mode_flag not in (MODE_ZC, MODE_ZH):
                raise EncryptorError(f'不支持的格式标志: {mode_flag} (此版本已移除 zj 自解模式)')

            # 强制要求用户提供密码
            if user_password is None:
                raise EncryptorError('解密需要提供密码')
            password_bytes = user_password.encode('utf-8')

            # 派生密钥并验证 HMAC
            cipher_key, mac_key = self._derive_keys(password_bytes, salt)
            mac = hmac.new(mac_key, digestmod=hashlib.sha256)
            mac.update(header_data[:header_size - SIG_LEN])

            # 解密
            with tempfile.NamedTemporaryFile(delete=False) as plain_temp:
                plain_path = plain_temp.name
                block_counter = 0
                while True:
                    encrypted_block = cipher_file.read(CHUNK_SIZE)
                    if not encrypted_block:
                        break
                    mac.update(encrypted_block)
                    keystream = self._keystream(cipher_key, nonce, block_counter, len(encrypted_block))
                    decrypted_block = bytes(e ^ k for e, k in zip(encrypted_block, keystream))
                    plain_temp.write(decrypted_block)
                    # 修正：按实际 HMAC 块数递增计数器
                    block_counter += (len(encrypted_block) + 31) // 32

                computed_signature = mac.digest()
                if not ignore_magic:
                    if not hmac.compare_digest(stored_signature, computed_signature):
                        plain_temp.close()
                        os.remove(plain_path)
                        raise EncryptorError('签名验证失败 (文件完整性受损或密码错误)')
                plain_temp.flush()

            # 解压缩
            with open(plain_path, 'rb') as plain_file, open(output_path, 'wb') as fout:
                decompressor = zlib.decompressobj()
                while True:
                    compressed_block = plain_file.read(CHUNK_SIZE)
                    if not compressed_block:
                        break
                    decompressed = decompressor.decompress(compressed_block)
                    if decompressed:
                        fout.write(decompressed)
                leftover = decompressor.flush()
                if leftover:
                    fout.write(leftover)

        # 清理临时文件
        os.remove(plain_path)
        os.remove(decoded_path)


# ******************** 便捷函数 ********************
def encrypt_file(input_path: str, output_path: str, password: str, mode: str = 'zh'):
    Encryptor(password).encrypt_stream(input_path, output_path, mode)

def decrypt_file(input_path: str, output_path: str, password: str = None, ignore_magic: bool = False):
    Encryptor().decrypt_stream(input_path, output_path, ignore_magic, user_password=password)


# ******************** 图形界面 (Tkinter) ********************
def gui_main():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print('错误：无法导入 tkinter，请确保 Python 安装了 Tk 支持。')
        sys.exit(1)

    class App:
        def __init__(self, root):
            self.root = root
            self.root.title('Unicode 加密工具 v10 (去ZJ版-修正)')
            self.root.resizable(False, False)

            self.mode = tk.StringVar(value='encrypt')
            self.enc_mode = tk.StringVar(value='zh')   # 加密模式选择
            self.input_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.password = tk.StringVar()

            self.create_widgets()

        def create_widgets(self):
            # 操作模式
            mode_frame = ttk.LabelFrame(self.root, text='操作模式', padding=5)
            mode_frame.grid(row=0, column=0, columnspan=4, padx=10, pady=5, sticky='ew')
            ttk.Radiobutton(mode_frame, text='加密', variable=self.mode,
                            value='encrypt', command=self.update_mode).grid(row=0, column=0, padx=5)
            ttk.Radiobutton(mode_frame, text='解密', variable=self.mode,
                            value='decrypt', command=self.update_mode).grid(row=0, column=1, padx=5)

            # 加密模式选择（仅加密时显示）
            self.enc_mode_label = ttk.Label(mode_frame, text='加密模式:')
            self.enc_mode_label.grid(row=0, column=2, padx=5)
            self.enc_mode_combo = ttk.Combobox(mode_frame, textvariable=self.enc_mode,
                                               values=['zh (汉字编码)', 'zc (Base-112)'], state='readonly', width=18)
            self.enc_mode_combo.grid(row=0, column=3, padx=5)
            self.enc_mode_combo.bind('<<ComboboxSelected>>', self.on_enc_mode_change)

            # 输入文件
            tk.Label(self.root, text='输入文件:').grid(row=1, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.input_path, width=50).grid(row=1, column=1, padx=5, pady=5)
            tk.Button(self.root, text='浏览...', command=self.browse_input).grid(row=1, column=2, padx=5, pady=5)

            # 输出文件
            tk.Label(self.root, text='输出文件:').grid(row=2, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.output_path, width=50).grid(row=2, column=1, padx=5, pady=5)
            tk.Button(self.root, text='浏览...', command=self.browse_output).grid(row=2, column=2, padx=5, pady=5)

            # 密码
            tk.Label(self.root, text='密码:').grid(row=3, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.password, width=50, show='*').grid(row=3, column=1, padx=5, pady=5)

            # 执行按钮
            self.run_button = tk.Button(self.root, text='执行', command=self.run)
            self.run_button.grid(row=4, column=1, padx=5, pady=10)

            # 状态栏
            self.status = tk.Label(self.root, text='就绪', relief='sunken', anchor='w')
            self.status.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky='ew')

            self.update_mode()

        def on_enc_mode_change(self, event=None):
            pass

        def update_mode(self):
            if self.mode.get() == 'encrypt':
                self.enc_mode_label.grid()
                self.enc_mode_combo.grid()
            else:
                self.enc_mode_label.grid_remove()
                self.enc_mode_combo.grid_remove()
            self.suggest_output()

        def browse_input(self):
            path = filedialog.askopenfilename(title='选择输入文件')
            if path:
                self.input_path.set(path)
                self.suggest_output()

        def browse_output(self):
            path = filedialog.asksaveasfilename(title='选择输出文件')
            if path:
                self.output_path.set(path)

        def suggest_output(self):
            input_file = self.input_path.get()
            if not input_file:
                return
            directory = os.path.dirname(input_file)
            basename = os.path.basename(input_file)
            if self.mode.get() == 'encrypt':
                suggestion = basename + '-enc'
            elif basename.endswith('-enc'):
                suggestion = basename[:-4] + '-dec'
            else:
                suggestion = basename + '-dec'
            self.output_path.set(os.path.join(directory, suggestion))

        def run(self):
            if not self.input_path.get():
                messagebox.showerror('错误', '请选择输入文件')
                return
            if not self.output_path.get():
                messagebox.showerror('错误', '请指定输出文件')
                return
            if not os.path.isfile(self.input_path.get()):
                messagebox.showerror('错误', '输入文件不存在')
                return

            try:
                self.status.config(text='正在处理...')
                self.root.update()

                if self.mode.get() == 'encrypt':
                    if not self.password.get():
                        messagebox.showerror('错误', '加密需要输入密码')
                        return
                    mode_str = self.enc_mode.get()
                    enc_mode = 'zh' if mode_str.startswith('zh') else 'zc'
                    encrypt_file(self.input_path.get(), self.output_path.get(),
                                 self.password.get(), mode=enc_mode)
                    msg = f"加密完成（{enc_mode.upper()}模式）！\n输出文件：{self.output_path.get()}"
                else:
                    pwd = self.password.get() if self.password.get() else None
                    try:
                        decrypt_file(self.input_path.get(), self.output_path.get(), password=pwd)
                        msg = f"解密完成！\n输出文件：{self.output_path.get()}"
                    except EncryptorError as e:
                        if '魔术头不匹配' in str(e):
                            retry = messagebox.askyesno(
                                '魔术头不匹配',
                                '文件的魔术头不匹配，可能是旧版本文件。\n是否尝试忽略魔术头并继续？'
                            )
                            if retry:
                                decrypt_file(self.input_path.get(), self.output_path.get(),
                                             password=pwd, ignore_magic=True)
                                msg = f"解密完成！\n输出文件：{self.output_path.get()}"
                            else:
                                raise
                        else:
                            raise
                self.status.config(text='完成')
                messagebox.showinfo('成功', msg)
            except Exception as e:
                self.status.config(text='错误')
                messagebox.showerror('错误', str(e))

    root = tk.Tk()
    app = App(root)
    root.mainloop()


# ******************** 命令行接口 ********************
def cli_main():
    parser = argparse.ArgumentParser(description='Unicode加密工具 v10（去ZJ版-修正）')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('mode', nargs='?', choices=['encrypt', 'decrypt'], help='操作模式')
    parser.add_argument('input', nargs='?', help='输入文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径（默认自动生成）')
    parser.add_argument('-p', '--password', help='密码')
    parser.add_argument('--enc-mode', choices=['zc', 'zh'], default='zh',
                        help='加密模式：zc (Base-112，膨胀率2x) 或 zh (汉字编码，膨胀率1x，默认)')
    parser.add_argument('--ignore-magic', action='store_true', help='忽略魔术头校验（用于解密旧版本文件）')
    args = parser.parse_args()

    if args.gui or (args.mode is None and args.input is None):
        gui_main()
        return

    if args.mode is None or args.input is None:
        parser.error('命令行模式需要指定 mode 和 input')

    if not os.path.isfile(args.input):
        print(f"错误：文件 {args.input} 不存在")
        return

    password = args.password if args.password else None
    if args.mode == 'encrypt' and password is None:
        password = getpass('请输入加密密码: ')
    elif args.mode == 'decrypt' and password is None:
        password = getpass('请输入解密密码: ')  # 强制要求密码

    # 自动生成输出文件名
    if args.output:
        output_path = args.output
    else:
        directory = os.path.dirname(args.input)
        basename = os.path.basename(args.input)
        if args.mode == 'encrypt':
            suggestion = basename + '-enc'
        elif basename.endswith('-enc'):
            suggestion = basename[:-4] + '-dec'
        else:
            suggestion = basename + '-dec'
        output_path = os.path.join(directory, suggestion)

    try:
        if args.mode == 'encrypt':
            encrypt_file(args.input, output_path, password, mode=args.enc_mode)
            print(f"加密完成（{args.enc_mode.upper()}模式），输出文件: {output_path}")
        else:
            decrypt_file(args.input, output_path, password=password, ignore_magic=args.ignore_magic)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")


if __name__ == '__main__':
    cli_main()