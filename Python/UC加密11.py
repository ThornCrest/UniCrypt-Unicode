#!/usr/bin/env python3
"""
Unicode 加密工具 v11（多算法版）—— 修正 ChaCha20 密钥长度
功能：将任意文件进行压缩、身份验证加密后，编码为 Unicode 字符存储；
      支持三种核心加密算法：
      - 's' : SHA256 + HMAC 流加密（原版，无需额外库）
      - 'a' : AES-128-CTR（需 pycryptodome）
      - 'c' : ChaCha20（需 pycryptodome）
      编码模式依旧支持 zc（Base-112）和 zh（汉字编码）。
加密流程：压缩 → 流加密 → HMAC‑SHA256 签名 → Unicode 编码 → 存储。
头部格式：MAGIC(4) + 编码模式(2) + 算法标识(1) + Salt(16) + Nonce(12) + 签名(32)
兼容性：可解密 v10 旧版文件（无算法标识，默认当作 's' 处理）。
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
MAGIC = b'UC11'            # 文件魔术头
SALT_LEN = 16              # 盐值长度（字节）
NONCE_LEN = 12             # 随机数长度（字节）
SIG_LEN = 32               # HMAC 签名长度（字节）
KEY_LEN_TOTAL = 64         # PBKDF2 派生总长度（加密密钥最大32 + HMAC密钥32）
PBKDF2_ITER = 600_000      # PBKDF2 迭代次数
CHUNK_SIZE = 65536         # 读写块大小

# 编码模式常量
MODE_ZC = b'zc'            # Base-112 编码（可见字符区）
MODE_ZH = b'zh'            # 汉字编码（CJK 基本区）

# 算法标识
ALGO_SHA = b's'            # 原版 SHA256 + HMAC 密钥流
ALGO_AES = b'a'            # AES-128-CTR（需 pycryptodome）
ALGO_CHACHA = b'c'         # ChaCha20（需 pycryptodome）
VALID_ALGOS = {ALGO_SHA, ALGO_AES, ALGO_CHACHA}

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
    def __init__(self):
        self.remainder = None

    def feed(self, chars: str) -> bytes:
        if self.remainder is not None:
            chars = self.remainder + chars
            self.remainder = None
        if len(chars) % 2 != 0:
            self.remainder = chars[-1]
            chars = chars[:-1]
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
    def __init__(self, password: str = None, algo: str = 's'):
        """
        :param password: 用户密码
        :param algo: 加密算法标识，'s' (SHA256), 'a' (AES), 'c' (ChaCha20)
        """
        if password is not None:
            self.password = password.encode('utf-8')
        else:
            self.password = None
        if algo not in ('s', 'a', 'c'):
            raise EncryptorError(f'不支持的算法: {algo}')
        self.algo = algo.encode('ascii')

    @staticmethod
    def _derive_keys(password_bytes: bytes, salt: bytes, cipher_len: int):
        """
        派生密钥材料。
        :param cipher_len: 加密密钥长度（对于 SHA/AES 为 16，ChaCha20 为 32）
        :return: (cipher_key, mac_key) 其中 mac_key 恒为 32 字节
        """
        total_len = cipher_len + 32
        key_material = hashlib.pbkdf2_hmac(
            'sha256', password_bytes, salt, PBKDF2_ITER, dklen=total_len
        )
        return key_material[:cipher_len], key_material[cipher_len:]

    @staticmethod
    def _keystream_sha(cipher_key: bytes, nonce: bytes, counter: int, length: int) -> bytes:
        """原版 SHA256+HMAC 密钥流生成"""
        key_stream = bytearray()
        current_counter = counter
        while len(key_stream) < length:
            counter_bytes = current_counter.to_bytes(4, 'big')
            key_stream.extend(
                hmac.new(cipher_key, nonce + counter_bytes, hashlib.sha256).digest()
            )
            current_counter += 1
        return bytes(key_stream[:length])

    def _encrypt_block(self, algo: bytes, cipher_key: bytes, nonce: bytes,
                       counter: int, plaintext: bytes, cipher_obj=None):
        """
        根据算法加密一块数据。
        对于 'a' 和 'c'，需要外部维护 cipher_obj（流密码状态）。
        返回 (密文, 新计数器, 新cipher_obj)
        """
        if algo == ALGO_SHA:
            keystream = self._keystream_sha(cipher_key, nonce, counter, len(plaintext))
            encrypted = bytes(p ^ k for p, k in zip(plaintext, keystream))
            # SHA256 模式的计数器按 HMAC 块数（32字节）递增
            counter += (len(plaintext) + 31) // 32
            return encrypted, counter, None
        elif algo == ALGO_AES:
            encrypted = cipher_obj.encrypt(plaintext)
            # AES-CTR 自动维护计数器，无需手动更新
            return encrypted, counter, cipher_obj
        elif algo == ALGO_CHACHA:
            encrypted = cipher_obj.encrypt(plaintext)
            return encrypted, counter, cipher_obj
        else:
            raise EncryptorError(f'未知算法: {algo}')

    def _create_cipher(self, algo: bytes, key: bytes, nonce: bytes):
        """根据算法创建流密码对象（仅用于 AES 和 ChaCha20）"""
        if algo == ALGO_AES:
            try:
                from Crypto.Cipher import AES
                from Crypto.Util import Counter
            except ImportError:
                raise EncryptorError('AES 模式需要安装 pycryptodome 库 (pip install pycryptodome)')
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, 'big') << 32)
            return AES.new(key, AES.MODE_CTR, counter=ctr)
        elif algo == ALGO_CHACHA:
            try:
                from Crypto.Cipher import ChaCha20
            except ImportError:
                raise EncryptorError('ChaCha20 模式需要安装 pycryptodome 库 (pip install pycryptodome)')
            return ChaCha20.new(key=key, nonce=nonce)
        else:
            return None

    def _cipher_len_for_algo(self, algo: bytes) -> int:
        """返回算法所需的加密密钥长度"""
        if algo in (ALGO_SHA, ALGO_AES):
            return 16
        elif algo == ALGO_CHACHA:
            return 32
        else:
            raise EncryptorError(f'未知算法: {algo}')

    def encrypt_stream(self, input_path: str, output_path: str, mode: str = 'zh'):
        """
        加密文件，支持模式: 'zc' 或 'zh'（默认 zh）
        """
        if mode not in ('zc', 'zh'):
            raise EncryptorError(f'不支持的加密模式: {mode}')
        mode_flag = MODE_ZC if mode == 'zc' else MODE_ZH
        algo_byte = self.algo

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
        cipher_len = self._cipher_len_for_algo(algo_byte)
        cipher_key, mac_key = self._derive_keys(self.password, salt, cipher_len)

        # 3. 构建头部并初始化 HMAC
        header_prefix = MAGIC + mode_flag + algo_byte + salt + nonce
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        mac.update(header_prefix)

        # 4. 加密压缩数据
        with tempfile.NamedTemporaryFile(delete=False) as cipher_temp:
            cipher_path = cipher_temp.name
            # 预留签名位置
            cipher_temp.write(header_prefix + bytes(SIG_LEN))

            block_counter = 0
            cipher_obj = None
            if algo_byte in (ALGO_AES, ALGO_CHACHA):
                cipher_obj = self._create_cipher(algo_byte, cipher_key, nonce)

            with open(compressed_path, 'rb') as comp_file:
                while True:
                    plain_block = comp_file.read(CHUNK_SIZE)
                    if not plain_block:
                        break
                    encrypted_block, block_counter, cipher_obj = self._encrypt_block(
                        algo_byte, cipher_key, nonce, block_counter, plain_block, cipher_obj
                    )
                    cipher_temp.write(encrypted_block)
                    mac.update(encrypted_block)

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

    def decrypt_stream(self, input_path: str, output_path: str,
                       ignore_magic: bool = False, user_password: str = None):
        # 1. 读取整个 Unicode 编码文件，解码为二进制
        with open(input_path, 'r', encoding='utf-8') as fin:
            full_content = fin.read()
        clean_content = full_content

        if not clean_content:
            raise EncryptorError('文件内容为空')

        # 根据首字符判断编码模式
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

        # 2. 解码为二进制密文
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

        # 3. 解析头部（兼容新旧格式）
        with open(decoded_path, 'rb') as cipher_file:
            first_7 = cipher_file.read(7)
            if len(first_7) < 7:
                raise EncryptorError('文件过短，无法读取头部')
            cipher_file.seek(0)

            magic = first_7[:4]
            mode_flag = first_7[4:6]
            maybe_algo = first_7[6:7]

            is_new_format = maybe_algo in VALID_ALGOS
            if is_new_format:
                header_size = len(MAGIC) + 2 + 1 + SALT_LEN + NONCE_LEN + SIG_LEN
                header_data = cipher_file.read(header_size)
                if len(header_data) < header_size:
                    raise EncryptorError('文件过短，无法读取完整头部')
                magic = header_data[:4]
                mode_flag = header_data[4:6]
                algo_byte = header_data[6:7]
                salt = header_data[7:7+SALT_LEN]
                nonce = header_data[7+SALT_LEN:7+SALT_LEN+NONCE_LEN]
                stored_sig = header_data[7+SALT_LEN+NONCE_LEN:7+SALT_LEN+NONCE_LEN+SIG_LEN]
                header_prefix = header_data[:-SIG_LEN]
            else:
                # 旧格式（无算法标识）
                header_size = len(MAGIC) + 2 + SALT_LEN + NONCE_LEN + SIG_LEN
                header_data = cipher_file.read(header_size)
                if len(header_data) < header_size:
                    raise EncryptorError('文件过短，无法读取完整头部')
                magic = header_data[:4]
                mode_flag = header_data[4:6]
                algo_byte = ALGO_SHA
                salt = header_data[6:6+SALT_LEN]
                nonce = header_data[6+SALT_LEN:6+SALT_LEN+NONCE_LEN]
                stored_sig = header_data[6+SALT_LEN+NONCE_LEN:6+SALT_LEN+NONCE_LEN+SIG_LEN]
                header_prefix = header_data[:-SIG_LEN]

            if not ignore_magic and magic != MAGIC:
                raise EncryptorError('魔术头不匹配 (文件可能被篡改或非本工具加密)')
            if mode_flag not in (MODE_ZC, MODE_ZH):
                raise EncryptorError(f'不支持的格式标志: {mode_flag}')
            if algo_byte not in VALID_ALGOS:
                raise EncryptorError(f'不支持的算法标识: {algo_byte}')

            if user_password is None:
                raise EncryptorError('解密需要提供密码')
            password_bytes = user_password.encode('utf-8')

            cipher_len = self._cipher_len_for_algo(algo_byte)
            cipher_key, mac_key = self._derive_keys(password_bytes, salt, cipher_len)

            # 验证 HMAC
            mac = hmac.new(mac_key, digestmod=hashlib.sha256)
            mac.update(header_prefix)

            # 解密
            with tempfile.NamedTemporaryFile(delete=False) as plain_temp:
                plain_path = plain_temp.name
                block_counter = 0
                cipher_obj = None
                if algo_byte in (ALGO_AES, ALGO_CHACHA):
                    cipher_obj = self._create_cipher(algo_byte, cipher_key, nonce)

                while True:
                    encrypted_block = cipher_file.read(CHUNK_SIZE)
                    if not encrypted_block:
                        break
                    mac.update(encrypted_block)
                    decrypted_block, block_counter, cipher_obj = self._encrypt_block(
                        algo_byte, cipher_key, nonce, block_counter, encrypted_block, cipher_obj
                    )
                    plain_temp.write(decrypted_block)

                computed_sig = mac.digest()
                if not ignore_magic:
                    if not hmac.compare_digest(stored_sig, computed_sig):
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

        # 清理
        os.remove(plain_path)
        os.remove(decoded_path)


# ******************** 便捷函数 ********************
def encrypt_file(input_path: str, output_path: str, password: str,
                 mode: str = 'zh', algo: str = 's'):
    Encryptor(password, algo).encrypt_stream(input_path, output_path, mode)

def decrypt_file(input_path: str, output_path: str, password: str = None,
                 ignore_magic: bool = False):
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
            self.root.title('Unicode 加密工具 v11 (多算法)')
            self.root.resizable(False, False)

            self.mode = tk.StringVar(value='encrypt')
            self.enc_mode = tk.StringVar(value='zh')
            self.algo = tk.StringVar(value='s')
            self.input_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.password = tk.StringVar()

            self.create_widgets()

        def create_widgets(self):
            mode_frame = ttk.LabelFrame(self.root, text='操作模式', padding=5)
            mode_frame.grid(row=0, column=0, columnspan=4, padx=10, pady=5, sticky='ew')
            ttk.Radiobutton(mode_frame, text='加密', variable=self.mode,
                            value='encrypt', command=self.update_mode).grid(row=0, column=0, padx=5)
            ttk.Radiobutton(mode_frame, text='解密', variable=self.mode,
                            value='decrypt', command=self.update_mode).grid(row=0, column=1, padx=5)

            self.enc_mode_label = ttk.Label(mode_frame, text='编码模式:')
            self.enc_mode_label.grid(row=0, column=2, padx=5)
            self.enc_mode_combo = ttk.Combobox(mode_frame, textvariable=self.enc_mode,
                                               values=['zh (汉字编码)', 'zc (Base-112)'], state='readonly', width=18)
            self.enc_mode_combo.grid(row=0, column=3, padx=5)
            self.enc_mode_combo.bind('<<ComboboxSelected>>', self.on_enc_mode_change)

            self.algo_label = ttk.Label(mode_frame, text='加密算法:')
            self.algo_label.grid(row=0, column=4, padx=5)
            self.algo_combo = ttk.Combobox(mode_frame, textvariable=self.algo,
                                           values=['SHA256 (默认)', 'AES-128-CTR', 'ChaCha20'],
                                           state='readonly', width=14)
            self.algo_combo.grid(row=0, column=5, padx=5)
            self.algo_combo.bind('<<ComboboxSelected>>', self.on_algo_change)

            tk.Label(self.root, text='输入文件:').grid(row=1, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.input_path, width=50).grid(row=1, column=1, padx=5, pady=5)
            tk.Button(self.root, text='浏览...', command=self.browse_input).grid(row=1, column=2, padx=5, pady=5)

            tk.Label(self.root, text='输出文件:').grid(row=2, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.output_path, width=50).grid(row=2, column=1, padx=5, pady=5)
            tk.Button(self.root, text='浏览...', command=self.browse_output).grid(row=2, column=2, padx=5, pady=5)

            tk.Label(self.root, text='密码:').grid(row=3, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.password, width=50, show='*').grid(row=3, column=1, padx=5, pady=5)

            self.run_button = tk.Button(self.root, text='执行', command=self.run)
            self.run_button.grid(row=4, column=1, padx=5, pady=10)

            self.status = tk.Label(self.root, text='就绪', relief='sunken', anchor='w')
            self.status.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky='ew')

            self.update_mode()

        def on_enc_mode_change(self, event=None):
            pass

        def on_algo_change(self, event=None):
            algo = self.algo.get()
            if algo in ('AES-128-CTR', 'ChaCha20'):
                try:
                    import Crypto
                except ImportError:
                    messagebox.showwarning('缺失依赖',
                        f'您选择了 {algo}，但未安装 pycryptodome。\n'
                        '请运行: pip install pycryptodome\n'
                        '或切换回 SHA256 模式。')
                    self.algo.set('SHA256 (默认)')

        def update_mode(self):
            if self.mode.get() == 'encrypt':
                self.enc_mode_label.grid()
                self.enc_mode_combo.grid()
                self.algo_label.grid()
                self.algo_combo.grid()
            else:
                self.enc_mode_label.grid_remove()
                self.enc_mode_combo.grid_remove()
                self.algo_label.grid_remove()
                self.algo_combo.grid_remove()
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
                    enc_mode_str = self.enc_mode.get()
                    enc_mode = 'zh' if enc_mode_str.startswith('zh') else 'zc'
                    algo_str = self.algo.get()
                    if algo_str.startswith('SHA256'):
                        algo = 's'
                    elif algo_str.startswith('AES'):
                        algo = 'a'
                    elif algo_str.startswith('ChaCha'):
                        algo = 'c'
                    else:
                        algo = 's'
                    if algo in ('a', 'c'):
                        try:
                            import Crypto
                        except ImportError:
                            raise EncryptorError(
                                f'算法 {algo_str} 需要 pycryptodome，请安装: pip install pycryptodome'
                            )
                    encrypt_file(self.input_path.get(), self.output_path.get(),
                                 self.password.get(), mode=enc_mode, algo=algo)
                    msg = f"加密完成（{algo.upper()}算法，{enc_mode.upper()}编码）！\n输出文件：{self.output_path.get()}"
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
    parser = argparse.ArgumentParser(description='Unicode加密工具 v11（多算法）')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('mode', nargs='?', choices=['encrypt', 'decrypt'], help='操作模式')
    parser.add_argument('input', nargs='?', help='输入文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径（默认自动生成）')
    parser.add_argument('-p', '--password', help='密码')
    parser.add_argument('--enc-mode', choices=['zc', 'zh'], default='zh',
                        help='编码模式：zc (Base-112) 或 zh (汉字编码，默认)')
    parser.add_argument('--algo', choices=['s', 'a', 'c'], default='s',
                        help='加密算法：s=SHA256(默认), a=AES-128-CTR, c=ChaCha20 (a和c需pycryptodome)')
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

    if args.mode == 'encrypt' and args.algo in ('a', 'c'):
        try:
            import Crypto
        except ImportError:
            print(f"错误：算法 {args.algo} 需要 pycryptodome，请安装: pip install pycryptodome")
            return

    password = args.password if args.password else None
    if args.mode == 'encrypt' and password is None:
        password = getpass('请输入加密密码: ')
    elif args.mode == 'decrypt' and password is None:
        password = getpass('请输入解密密码: ')

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
            encrypt_file(args.input, output_path, password,
                         mode=args.enc_mode, algo=args.algo)
            print(f"加密完成（{args.algo.upper()}算法，{args.enc_mode.upper()}编码），输出文件: {output_path}")
        else:
            decrypt_file(args.input, output_path, password=password,
                         ignore_magic=args.ignore_magic)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")


if __name__ == '__main__':
    cli_main()