#!/usr/bin/env python3
"""
Unicode 加密工具
功能：将任意文件进行压缩、身份验证加密后，编码为可见 Unicode 字符存储；
      也可反向解密还原。
加密流程：压缩 → AES‑CTR 等价流加密（HMAC‑SHA256 作为密钥流）→ HMAC 签名 → Base‑112 编码为 Unicode。
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
BASE = 112                 # 编码基：将每个字节拆分为两个 0~111 的值
START = 768                # Unicode 起始码点（用于可见字符范围）
MAGIC = b'UC08'            # 文件魔术头
SALT_LEN = 16              # 盐值长度（字节）
NONCE_LEN = 12             # 随机数长度（字节）
SIG_LEN = 32               # HMAC 签名长度（字节）
KEY_LEN = 48               # 派生密钥总长度（加密密钥16 + HMAC密钥32）
PBKDF2_ITER = 600_000      # PBKDF2 迭代次数
CHUNK_SIZE = 65536         # 读写块大小

class EncryptorError(Exception):
    """加密/解密过程中的自定义异常。"""
    pass


# ******************** Base‑112 Unicode 编解码 ********************
def to_chars(data: bytes) -> str:
    """
    将原始字节流转换为 Base‑112 编码的 Unicode 字符串。
    每个字节拆分为两个 0~BASE-1 的值，并映射到 START 起始的字符区。
    """
    result = []
    for byte in data:
        high = byte // BASE
        low = byte % BASE
        result.append(chr(START + high))
        result.append(chr(START + low))
    return ''.join(result)


def from_chars(s: str) -> bytes:
    """
    将 Base‑112 编码的 Unicode 字符串还原为原始字节流。
    传入字符串长度必须是偶数，每个字符必须位于 [START, START+BASE) 区间。
    """
    if len(s) % 2 != 0:
        raise EncryptorError('编码字符串长度必须为偶数')
    result = bytearray()
    for i in range(0, len(s), 2):
        high_val = ord(s[i]) - START
        low_val = ord(s[i+1]) - START
        if not (0 <= high_val < BASE and 0 <= low_val < BASE):
            raise EncryptorError(f"非法字符: U+{ord(s[i]):04X}")
        result.append(high_val * BASE + low_val)
    return bytes(result)


# ******************** 流式编解码适配器 ********************
class StreamEncoder:
    """
    将二进制数据流式编码为 Unicode 字符，并写入文本文件。
    """
    def __init__(self, text_file):
        self.file = text_file

    def feed(self, data: bytes):
        """逐块编码并写入文件。"""
        for byte in data:
            high = START + byte // BASE
            low = START + byte % BASE
            self.file.write(chr(high))
            self.file.write(chr(low))

    def flush(self):
        """流编码器无需缓冲，直接 pass。"""
        pass


class StreamDecoder:
    """
    从文本文件流式读取 Unicode 字符，解码为原始二进制数据。
    """
    def __init__(self):
        self.buffer = []     # 存储未配对的半字节值

    def feed(self, chars: str) -> bytes:
        """
        接收一个字符块，返回全部可解码的字节。
        """
        for ch in chars:
            code = ord(ch)
            if not START <= code < START + BASE:
                raise EncryptorError(f"流解码错误：检测到非法 Unicode 字符 U+{code:04X}")
            self.buffer.append(code - START)
        # 当缓冲区中有至少两个半字节时配对输出
        output = bytearray()
        while len(self.buffer) >= 2:
            high = self.buffer[0]
            low = self.buffer[1]
            output.append(high * BASE + low)
            self.buffer = self.buffer[2:]
        return bytes(output)

    def flush(self) -> bytes:
        """确保没有残留的半字节。"""
        if self.buffer:
            raise EncryptorError('不完整的字符对')
        return b''


# ******************** 加密/解密核心 ********************
class Encryptor:
    """执行文件加密和解密的控制器。"""

    def __init__(self, password: str):
        self.password = password.encode('utf-8')

    def _derive_keys(self, salt: bytes):
        """
        基于密码和盐值派生 48 字节密钥材料：
        前 16 字节 → 加密密钥 (cipher_key)
        后 32 字节 → HMAC 密钥 (mac_key)
        """
        key_material = hashlib.pbkdf2_hmac(
            'sha256', self.password, salt, PBKDF2_ITER, dklen=KEY_LEN
        )
        cipher_key = key_material[:16]
        mac_key = key_material[16:]
        return cipher_key, mac_key

    def _keystream(self, cipher_key: bytes, nonce: bytes, counter: int, length: int) -> bytes:
        """
        生成指定长度的密钥流（CTR 模式）。
        使用 HMAC-SHA256(cipher_key, nonce || counter_be) 作为伪随机生成器。
        """
        key_stream = bytearray()
        current_counter = counter
        while len(key_stream) < length:
            counter_bytes = current_counter.to_bytes(4, 'big')
            key_stream.extend(
                hmac.new(cipher_key, nonce + counter_bytes, hashlib.sha256).digest()
            )
            current_counter += 1
        return bytes(key_stream[:length])

    def encrypt_stream(self, input_path: str, output_path: str):
        """
        加密文件：
        1. 读取明文并 zlib 压缩
        2. 生成随机盐和 nonce
        3. 加密压缩数据（密钥流异或）
        4. 计算整个密文的 HMAC 签名
        5. 将头部（魔数+标志+盐+nonce+签名）+ 密文二进制数据写入临时文件
        6. 将临时文件内容进行 Unicode 编码，写入最终输出文件
        """
        # --- 第一步：压缩输入文件到临时文件 ---
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
            # 临时文件关闭后数据保留

        # --- 第二步：生成盐、nonce，派生密钥 ---
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        cipher_key, mac_key = self._derive_keys(salt)
        compression_flag = b'\x01'   # 1 表示已压缩

        # --- 第三步：构建头部并初始化 HMAC ---
        header_prefix = MAGIC + compression_flag + salt + nonce
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        mac.update(header_prefix)

        # --- 第四步：加密压缩数据并写入密文临时文件 ---
        with tempfile.NamedTemporaryFile(delete=False) as cipher_temp:
            cipher_path = cipher_temp.name
            # 预留签名位置（先写 32 个零字节）
            cipher_temp.write(header_prefix + bytes(SIG_LEN))

            block_counter = 0
            with open(compressed_path, 'rb') as compressed_file:
                while True:
                    plain_block = compressed_file.read(CHUNK_SIZE)
                    if not plain_block:
                        break
                    # 生成密钥流
                    keystream = self._keystream(cipher_key, nonce, block_counter, len(plain_block))
                    # 异或加密
                    encrypted_block = bytes(p ^ k for p, k in zip(plain_block, keystream))
                    cipher_temp.write(encrypted_block)
                    # 更新 HMAC（覆盖密文）
                    mac.update(encrypted_block)
                    block_counter += 1

            # 计算最终签名并回填到头部预留位置
            signature = mac.digest()
            cipher_temp.seek(len(header_prefix))
            cipher_temp.write(signature)
            cipher_temp.flush()

        # --- 第五步：将密文二进制文件进行 Unicode 编码写入输出 ---
        with open(cipher_path, 'rb') as cipher_file, \
             open(output_path, 'w', encoding='utf-8') as output_file:
            encoder = StreamEncoder(output_file)
            while True:
                chunk = cipher_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                encoder.feed(chunk)
            encoder.flush()

        # --- 清理临时文件 ---
        os.remove(compressed_path)
        os.remove(cipher_path)

    def decrypt_stream(self, input_path: str, output_path: str, ignore_magic: bool = False):
        """
        解密文件：
        1. 将 Unicode 编码的输入文件流式解码为二进制密文临时文件
        2. 读取并验证头部（魔数、压缩标志）
        3. 派生密钥，计算 HMAC 并验证签名
        4. 解密数据（密钥流异或）
        5. 解压缩并写入最终输出文件
        """
        # --- 第一步：Unicode 解码输入文件，得到二进制密文临时文件 ---
        with tempfile.NamedTemporaryFile(delete=False) as decoded_temp:
            decoded_path = decoded_temp.name
            with open(input_path, 'r', encoding='utf-8') as fin:
                decoder = StreamDecoder()
                while True:
                    chars = fin.read(CHUNK_SIZE)
                    if not chars:
                        break
                    binary_chunk = decoder.feed(chars)
                    if binary_chunk:
                        decoded_temp.write(binary_chunk)
                remaining = decoder.flush()
                if remaining:
                    decoded_temp.write(remaining)
            decoded_temp.flush()

        # --- 第二步：读取密文头部 ---
        with open(decoded_path, 'rb') as cipher_file:
            header_size = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + SIG_LEN
            header_data = cipher_file.read(header_size)
            if len(header_data) < header_size:
                raise EncryptorError('文件过短，无法读取完整头部')

            magic = header_data[0:4]
            flag = header_data[4:5]
            salt = header_data[5:5+SALT_LEN]
            nonce = header_data[5+SALT_LEN:5+SALT_LEN+NONCE_LEN]
            stored_signature = header_data[5+SALT_LEN+NONCE_LEN:5+SALT_LEN+NONCE_LEN+SIG_LEN]

            # 验证魔数和压缩标志（除非显式忽略）
            if not ignore_magic and magic != MAGIC:
                raise EncryptorError('魔术头不匹配 (文件可能被篡改或非本工具加密)')
            if flag != b'\x01':
                raise EncryptorError('不支持的压缩标志')

            # --- 第三步：派生密钥并初始化 HMAC ---
            cipher_key, mac_key = self._derive_keys(salt)
            mac = hmac.new(mac_key, digestmod=hashlib.sha256)
            mac.update(header_data[:header_size - SIG_LEN])  # 更新除签名外的头部

            # --- 第四步：解密数据块并写入临时文件 ---
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
                    block_counter += 1

                # 验证签名
                computed_signature = mac.digest()
                if not ignore_magic:
                    if not hmac.compare_digest(stored_signature, computed_signature):
                        plain_temp.close()
                        os.remove(plain_path)
                        raise EncryptorError('签名验证失败 (文件完整性受损或密码错误)')
                plain_temp.flush()

            # --- 第五步：解压缩数据并写入最终输出文件 ---
            with open(plain_path, 'rb') as plain_file, \
                 open(output_path, 'wb') as fout:
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

        # --- 清理临时文件 ---
        os.remove(plain_path)
        os.remove(decoded_path)


# ******************** 便捷函数（供 GUI/CLI 调用） ********************
def encrypt_file(input_path: str, output_path: str, password: str):
    Encryptor(password).encrypt_stream(input_path, output_path)


def decrypt_file(input_path: str, output_path: str, password: str, ignore_magic: bool = False):
    Encryptor(password).decrypt_stream(input_path, output_path, ignore_magic)


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
            self.root.title('Unicode 加密工具 v7.5')
            self.root.resizable(False, False)

            self.mode = tk.StringVar(value='encrypt')
            self.input_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.password = tk.StringVar()

            self.create_widgets()

        def create_widgets(self):
            # 模式选择
            mode_frame = ttk.LabelFrame(self.root, text='操作模式', padding=5)
            mode_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5, sticky='ew')
            ttk.Radiobutton(mode_frame, text='加密', variable=self.mode,
                            value='encrypt', command=self.update_mode).grid(row=0, column=0, padx=5)
            ttk.Radiobutton(mode_frame, text='解密', variable=self.mode,
                            value='decrypt', command=self.update_mode).grid(row=0, column=1, padx=5)

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

        def update_mode(self):
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
            if not self.password.get():
                messagebox.showerror('错误', '请输入密码')
                return
            if not os.path.isfile(self.input_path.get()):
                messagebox.showerror('错误', '输入文件不存在')
                return

            try:
                self.status.config(text='正在处理...')
                self.root.update()

                if self.mode.get() == 'encrypt':
                    encrypt_file(self.input_path.get(), self.output_path.get(), self.password.get())
                    msg = f"加密完成！\n输出文件：{self.output_path.get()}"
                else:
                    try:
                        decrypt_file(self.input_path.get(), self.output_path.get(), self.password.get())
                        msg = f"解密完成！\n输出文件：{self.output_path.get()}"
                    except EncryptorError as e:
                        if '魔术头不匹配' in str(e):
                            # 询问是否忽略魔术头
                            retry = messagebox.askyesno(
                                '魔术头不匹配',
                                '文件的魔术头不匹配，可能是旧版本文件。\n是否尝试忽略魔术头并继续？'
                            )
                            if retry:
                                decrypt_file(self.input_path.get(), self.output_path.get(),
                                             self.password.get(), ignore_magic=True)
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
    parser = argparse.ArgumentParser(description='Unicode加密工具 v7.5')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('mode', nargs='?', choices=['encrypt', 'decrypt'], help='操作模式')
    parser.add_argument('input', nargs='?', help='输入文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径（默认自动生成）')
    parser.add_argument('-p', '--password', help='密码（若不提供则交互输入）')
    parser.add_argument('--ignore-magic', action='store_true', help='忽略魔术头校验（用于解密旧版本文件）')
    args = parser.parse_args()

    # 如果要求 GUI 或未提供命令行参数，启动图形界面
    if args.gui or (args.mode is None and args.input is None):
        gui_main()
        return

    if args.mode is None or args.input is None:
        parser.error('命令行模式需要指定 mode 和 input')

    if not os.path.isfile(args.input):
        print(f"错误：文件 {args.input} 不存在")
        return

    password = args.password if args.password else getpass('请输入密码: ')

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
            encrypt_file(args.input, output_path, password)
            print(f"加密完成，输出文件: {output_path}")
        else:
            decrypt_file(args.input, output_path, password, ignore_magic=args.ignore_magic)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")


if __name__ == '__main__':
    cli_main()