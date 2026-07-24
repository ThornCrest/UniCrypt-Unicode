#!/usr/bin/env python3
"""
Unicode 范围加密工具 (版本 3.0) - 包含命令行和图形界面
将任意文件加密为由 U+0300..U+036F 字符组成的文本文件。
支持可选压缩、HMAC 签名、PBKDF2 密钥派生。
"""

import os
import zlib
import hashlib
import hmac
import argparse
import sys
from math import ceil
from getpass import getpass

# ==================== 常量定义 ====================
BASE = 112                     # 编码基数（U+0300..U+036F 共 112 个字符）
START = 0x0300                  # Unicode 起始码点
MAGIC = b'UC03'                 # 魔术头，标识版本 3.0
SALT_LEN = 16                   # 盐值长度（字节）
NONCE_LEN = 12                  # nonce 长度（字节）
SIG_LEN = 32                    # HMAC-SHA256 签名长度（字节）
KEY_LEN = 32                    # 派生密钥总长度（加密密钥16 + 认证密钥16）
PBKDF2_ITER = 100000            # PBKDF2 迭代次数
BLOCK_SIZE = 32                 # 流加密的块大小（HMAC 输出长度）

# ==================== 异常类 ====================
class EncryptorError(Exception):
    """加密/解密过程中发生的错误"""
    pass

# ==================== 核心编码器 ====================
def to_chars(data: bytes) -> str:
    """
    将字节数据编码为 U+0300..U+036F 范围内的字符字符串。
    每字节拆分为两个基数 BASE 的数字，映射为两个 Unicode 字符。
    """
    chars = []
    for b in data:
        high = b // BASE
        low = b % BASE
        chars.append(chr(START + high))
        chars.append(chr(START + low))
    return ''.join(chars)

def from_chars(s: str) -> bytes:
    """
    将 U+0300..U+036F 字符串解码回原始字节数据。
    每两个字符组合还原一个字节。
    """
    if len(s) % 2 != 0:
        raise EncryptorError("编码字符串长度必须为偶数")
    data = bytearray()
    for i in range(0, len(s), 2):
        c1 = ord(s[i]) - START
        c2 = ord(s[i+1]) - START
        if not (0 <= c1 < BASE and 0 <= c2 < BASE):
            raise EncryptorError(f"发现范围外的字符: U+{ord(s[i]):04X} 或 U+{ord(s[i+1]):04X}")
        data.append(c1 * BASE + c2)
    return bytes(data)

# ==================== 加密器类 ====================
class Encryptor:
    """
    文件加密器，支持压缩、HMAC 签名、PBKDF2 密钥派生。
    输出格式：MAGIC(4) + flag(1) + salt(16) + nonce(12) + signature(32) + ciphertext
    """

    def __init__(self, password: str):
        """
        初始化加密器。
        :param password: 用户密码（字符串）
        """
        self.password = password.encode('utf-8')

    def _derive_keys(self, salt: bytes) -> tuple[bytes, bytes]:
        """
        使用 PBKDF2 从密码和盐派生加密密钥和认证密钥。
        :param salt: 16 字节随机盐
        :return: (enc_key, mac_key) 各 16 字节
        """
        key_material = hashlib.pbkdf2_hmac('sha256', self.password, salt, PBKDF2_ITER, dklen=KEY_LEN)
        return key_material[:16], key_material[16:]

    def _encrypt_stream(self, data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
        """
        使用基于 HMAC-SHA256 的计数器模式加密数据。
        :param data: 明文数据（可能已压缩）
        :param enc_key: 16 字节加密密钥
        :param nonce: 12 字节随机数
        :return: 密文
        """
        ciphertext = bytearray()
        num_blocks = ceil(len(data) / BLOCK_SIZE)
        for i in range(num_blocks):
            counter = i.to_bytes(4, 'big')
            prf_input = nonce + counter
            keystream = hmac.new(enc_key, prf_input, hashlib.sha256).digest()
            block = data[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE]
            for j in range(len(block)):
                ciphertext.append(block[j] ^ keystream[j])
        return bytes(ciphertext)

    def _decrypt_stream(self, ciphertext: bytes, enc_key: bytes, nonce: bytes) -> bytes:
        """解密（与加密完全相同，异或操作可逆）"""
        return self._encrypt_stream(ciphertext, enc_key, nonce)

    def encrypt(self, data: bytes, compress: bool = False) -> bytes:
        """
        加密数据，返回待编码的打包字节流。
        :param data: 原始数据（字节）
        :param compress: 是否先压缩
        :return: 打包后的字节流（包含魔术头、盐、nonce、签名、密文）
        """
        # 压缩
        if compress:
            data_to_encrypt = zlib.compress(data)
            flag = b'\x01'
        else:
            data_to_encrypt = data
            flag = b'\x00'

        # 生成随机盐和 nonce
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)

        # 派生密钥
        enc_key, mac_key = self._derive_keys(salt)

        # 加密
        ciphertext = self._encrypt_stream(data_to_encrypt, enc_key, nonce)

        # 计算签名（对密文）
        signature = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()

        # 打包
        packed = MAGIC + flag + salt + nonce + signature + ciphertext
        return packed

    def decrypt(self, packed: bytes) -> bytes:
        """
        解密打包的数据，返回原始数据。
        :param packed: 打包后的字节流（包含魔术头、盐、nonce、签名、密文）
        :return: 解密并解压后的原始数据
        """
        # 检查魔术头
        if len(packed) < len(MAGIC):
            raise EncryptorError("数据太短，不是有效的加密包")
        if packed[:len(MAGIC)] != MAGIC:
            raise EncryptorError("魔术头不匹配，可能不是本程序生成的文件")

        # 解析各部分
        offset = len(MAGIC)
        flag = packed[offset:offset+1]
        salt = packed[offset+1:offset+1+SALT_LEN]
        nonce = packed[offset+1+SALT_LEN:offset+1+SALT_LEN+NONCE_LEN]
        signature = packed[offset+1+SALT_LEN+NONCE_LEN:offset+1+SALT_LEN+NONCE_LEN+SIG_LEN]
        ciphertext = packed[offset+1+SALT_LEN+NONCE_LEN+SIG_LEN:]

        # 派生密钥
        enc_key, mac_key = self._derive_keys(salt)

        # 验证签名
        expected_sig = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            raise EncryptorError("签名验证失败！数据可能被篡改或密码错误。")

        # 解密
        plain_compressed = self._decrypt_stream(ciphertext, enc_key, nonce)

        # 解压
        if flag == b'\x01':
            return zlib.decompress(plain_compressed)
        elif flag == b'\x00':
            return plain_compressed
        else:
            raise EncryptorError(f"未知的压缩标志: {flag}")

# ==================== 文件处理函数 ====================
def encrypt_file(input_path: str, output_path: str, password: str, compress: bool):
    """加密文件，写入输出路径"""
    with open(input_path, 'rb') as f:
        data = f.read()

    enc = Encryptor(password)
    packed = enc.encrypt(data, compress)

    encoded = to_chars(packed)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(encoded)

def decrypt_file(input_path: str, output_path: str, password: str):
    """解密文件，写入输出路径"""
    with open(input_path, 'r', encoding='utf-8') as f:
        encoded = f.read().strip()

    packed = from_chars(encoded)
    enc = Encryptor(password)
    plaintext = enc.decrypt(packed)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

# ==================== 图形用户界面 (Tkinter) ====================
def gui_main():
    """启动 Tkinter 图形界面"""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("错误：无法导入 tkinter，请确保 Python 安装了 Tk 支持。")
        sys.exit(1)

    class EncryptorGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("Unicode 加密工具 v2.0")
            self.root.resizable(False, False)

            # 变量
            self.mode = tk.StringVar(value="encrypt")
            self.input_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.password = tk.StringVar()
            self.compress = tk.BooleanVar(value=False)

            # 创建界面
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

            # 压缩选项（仅加密时有效）
            self.compress_check = ttk.Checkbutton(self.root, text="启用压缩 (减小体积)",
                                                   variable=self.compress, state="normal")
            self.compress_check.grid(row=4, column=1, padx=5, pady=5, sticky="w")

            # 执行按钮
            self.run_button = ttk.Button(self.root, text="执行", command=self.run)
            self.run_button.grid(row=5, column=1, padx=5, pady=10)

            # 状态栏
            self.status = ttk.Label(self.root, text="就绪", relief="sunken", anchor="w")
            self.status.grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

            self.update_mode()

        def update_mode(self):
            """根据模式更新界面状态"""
            if self.mode.get() == "encrypt":
                self.compress_check.config(state="normal")
            else:
                self.compress_check.config(state="disabled")
                self.compress.set(False)

        def browse_input(self):
            filename = filedialog.askopenfilename(title="选择输入文件")
            if filename:
                self.input_path.set(filename)
                # 自动生成输出文件名建议
                self.suggest_output()

        def browse_output(self):
            filename = filedialog.asksaveasfilename(title="选择输出文件")
            if filename:
                self.output_path.set(filename)

        def suggest_output(self):
            """根据输入文件和模式建议输出文件名"""
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
            """执行加密/解密"""
            # 验证输入
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
                                 self.password.get(), self.compress.get())
                    msg = f"加密完成！\n输出文件：{self.output_path.get()}"
                else:
                    decrypt_file(self.input_path.get(), self.output_path.get(),
                                 self.password.get())
                    msg = f"解密完成！\n输出文件：{self.output_path.get()}"

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
    parser = argparse.ArgumentParser(description="使用Unicode特殊字符加密/解密文件")
    parser.add_argument('--gui', action='store_true', help="启动图形界面")
    parser.add_argument('mode', nargs='?', choices=['encrypt', 'decrypt'], help="操作模式（命令行模式需要）")
    parser.add_argument('input', nargs='?', help="输入文件路径")
    parser.add_argument('-o', '--output', help="输出文件路径（默认自动生成）")
    parser.add_argument('-p', '--password', help="密码（若不提供则交互输入）")
    parser.add_argument('-c', '--compress', action='store_true', help="加密时启用压缩")
    args = parser.parse_args()

    # 如果指定 --gui 或没有提供必要参数，启动 GUI
    if args.gui or (args.mode is None and args.input is None):
        gui_main()
        return

    # 命令行模式需要 mode 和 input
    if args.mode is None or args.input is None:
        parser.error("命令行模式需要指定 mode 和 input")

    # 检查输入文件
    if not os.path.isfile(args.input):
        print(f"错误：文件 {args.input} 不存在")
        return

    # 获取密码
    if args.password:
        password = args.password
    else:
        password = getpass("请输入密码: ")

    # 生成输出路径
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
            encrypt_file(args.input, output_path, password, args.compress)
            comp_info = "（已压缩）" if args.compress else "（未压缩）"
            print(f"加密完成，输出文件: {output_path} {comp_info}")
        else:
            decrypt_file(args.input, output_path, password)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")

if __name__ == "__main__":
    cli_main()