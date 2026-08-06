#!/usr/bin/env python3
"""
Unicode 加密工具 v12
（多算法 + PBKDF2迭代可调版）—— 修正 ChaCha20 密钥长度
  v11.1 改进点：
    [P0-1] 默认算法改为 AES-128-CTR（未装 pycryptodome 自动降级 SHA256）
    [P0-2] 解密端改为流式字符解码，避免大文件一次性读入 OOM
    [P1-A1] 临时文件 try/finally 保底删除 + secure_delete 安全覆写
    [P1-A3] 新增 PBKDF2 迭代次数可调（CLI --iter / GUI 输入框），
           头部新增 'pb' 标识： pb(T/F) + 8 位补 0 数字
功能：将任意文件进行压缩、身份验证加密后，编码为 Unicode 字符存储；
      支持三种核心加密算法：
      - 's' : SHA256 + HMAC 流加密（原版，无需额外库）
      - 'a' : AES-128-CTR（需 pycryptodome）—— 默认
      - 'c' : ChaCha20（需 pycryptodome）
      编码模式依旧支持 zc（Base-112）和 zh（汉字编码）。
加密流程：压缩 → 流加密 → HMAC‑SHA256 签名 → Unicode 编码 → 存储。
头部格式：
  旧版 v10/v11(无pb):   MAGIC(4) + 编码模式(2) + 算法标识(1) + Salt(16) + Nonce(12) + 签名(32)  = 67B
  新版 v11.1(含pb):     MAGIC(4) + 编码模式(2) + 算法标识(1) + "pb"(2) + T/F(1) + 8位iter数字(8)
                       + Salt(16) + Nonce(12) + 签名(32)  = 78B
兼容性：可解密 v10 旧版文件（无算法标识，默认当作 's' 处理）
        可解密 v11 原版文件（无 pb 标识，PBKDF2 用默认 600000）。
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
MAGIC = b'UC12'            # 文件魔术头
SALT_LEN = 16              # 盐值长度（字节）
NONCE_LEN = 12             # 随机数长度（字节）
SIG_LEN = 32               # HMAC 签名长度（字节）
KEY_LEN_TOTAL = 64         # PBKDF2 派生总长度（加密密钥最大32 + HMAC密钥32）
PBKDF2_ITER_DEFAULT = 600_000   # PBKDF2 默认迭代次数
CHUNK_SIZE = 65536         # 读写块大小
CHAR_CHUNK = 131072        # 流式字符解码块大小（128K 字符，zh ≈ 384KB 内存）
SECURE_DELETE_PASSES = 2   # 安全覆写次数（HDD 用，SSD 效果有限但聊胜于无）

# 编码模式常量
MODE_ZC = b'zc'            # Base-112 编码（可见字符区）
MODE_ZH = b'zh'            # 汉字编码（CJK 基本区）

# 算法标识
ALGO_SHA = b's'            # 原版 SHA256 + HMAC 密钥流
ALGO_AES = b'a'            # AES-128-CTR（需 pycryptodome）
ALGO_CHACHA = b'c'         # ChaCha20（需 pycryptodome）
VALID_ALGOS = {ALGO_SHA, ALGO_AES, ALGO_CHACHA}

# PBKDF2迭代（pb）头部扩展标识
PB_FLAG = b'pb'            # 2字节固定标识
PB_TRUE = b'T'             # 使用自定义迭代次数
PB_FALSE = b'F'            # 使用默认迭代次数
PB_NUM_LEN = 8             # 8 位 ASCII 十进制数字，不足前面补 0

# zc 模式参数（Base-112，可见字符区 U+0300 ~ U+036F）
ZC_BASE = 112
ZC_START = 0x0300

# zh 模式参数（汉字编码，CJK 统一表意文字区 U+4E00 ~ U+4EFF）
ZH_BASE = 256
ZH_START = 0x4E00

class EncryptorError(Exception):
    """加密/解密过程中的自定义异常。"""
    pass


# ******************** 辅助：环境探测与安全删除 ********************

def _detect_default_algo() -> str:
    """智能选择默认算法：装了 pycryptodome 就默认 AES，否则 SHA256。"""
    try:
        import Crypto  # noqa: F401
        return 'a'
    except ImportError:
        # 没装 pycryptodome，默认回退到零依赖 SHA256（但打印一次警告）
        return 's'


def _print_default_algo_note_once(algo_used: str):
    """第一次实际加密时，若因未装 pycryptodome 降级 SHA 给一行提示。"""
    # 只提示一次，用全局标志
    global _DEFAULT_ALGO_NOTICE_SHOWN
    if _DEFAULT_ALGO_NOTICE_SHOWN:
        return
    _DEFAULT_ALGO_NOTICE_SHOWN = True
    if algo_used == 's':
        print('[提示] 当前默认使用零依赖的 SHA256 算法。'
              '如需更高安全强度的标准 AES-128-CTR，请运行: pip install pycryptodome')


_DEFAULT_ALGO_NOTICE_SHOWN = False
DEFAULT_ALGO = _detect_default_algo()


def secure_delete(path: str, passes: int = SECURE_DELETE_PASSES):
    """安全删除：先多次覆写随机字节再 remove（HDD 有效，SSD 无法保证但仍尝试）。
    文件不存在时静默忽略，任何异常吞掉避免影响主流程。
    """
    if not path or not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        if size > 0:
            with open(path, 'r+b') as f:
                for _ in range(max(1, passes)):
                    f.seek(0)
                    pos = 0
                    # 大文件按 1MB 块写，省内存
                    block = 1024 * 1024
                    while pos < size:
                        write_len = min(block, size - pos)
                        f.write(os.urandom(write_len))
                        pos += write_len
                    f.flush()
                    os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        # 任何情况都不让 secure_delete 搞砸主流程
        try:
            os.remove(path)
        except Exception:
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
    def __init__(self, password: str = None, algo: str = None,
                 pbkdf2_iter: int = None):
        """
        :param password: 用户密码
        :param algo: 加密算法标识，None=自动探测 ('s' SHA256, 'a' AES, 'c' ChaCha20)
        :param pbkdf2_iter: PBKDF2 迭代次数；None = 默认 600000 且头部 pb=F
                            非 None 值 = 头部 pb=T 并写入 8 位数字
        """
        if password is not None:
            self.password = password.encode('utf-8')
        else:
            self.password = None
        # 算法：None → 默认智能选
        if algo is None:
            algo = DEFAULT_ALGO
        if algo not in ('s', 'a', 'c'):
            raise EncryptorError(f'不支持的算法: {algo}')
        self.algo = algo.encode('ascii')
        _print_default_algo_note_once(algo)

        # PBKDF2 iter
        if pbkdf2_iter is None:
            self.pbkdf2_iter = PBKDF2_ITER_DEFAULT
            self.use_custom_pbkdf2 = False   # 写 pb=F
        else:
            if not isinstance(pbkdf2_iter, int) or pbkdf2_iter < 1000:
                raise EncryptorError(f'PBKDF2 迭代次数必须是 >=1000 的整数，收到: {pbkdf2_iter}')
            # 8 位数字最大 99999999（上限够用到天荒地老）
            if pbkdf2_iter > 99_999_999:
                raise EncryptorError(f'PBKDF2 迭代次数过大，上限 99999999')
            self.pbkdf2_iter = pbkdf2_iter
            self.use_custom_pbkdf2 = True    # 写 pb=T

    @staticmethod
    def _derive_keys(password_bytes: bytes, salt: bytes,
                     cipher_len: int, iter_count: int) -> tuple:
        """
        派生密钥材料。
        :param cipher_len: 加密密钥长度（对于 SHA/AES 为 16，ChaCha20 为 32）
        :param iter_count: 实际使用的 PBKDF2 迭代次数
        :return: (cipher_key, mac_key) 其中 mac_key 恒为 32 字节
        """
        total_len = cipher_len + 32
        key_material = hashlib.pbkdf2_hmac(
            'sha256', password_bytes, salt, iter_count, dklen=total_len
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

        # 构造 PBKDF2 扩展段：pb(T/F) + 8位数字
        pb_iter_str = f"{self.pbkdf2_iter:0{PB_NUM_LEN}d}"
        if len(pb_iter_str) != PB_NUM_LEN:
            raise EncryptorError(f'迭代次数格式化错误: {pb_iter_str}')
        pb_segment = (PB_FLAG
                      + (PB_TRUE if self.use_custom_pbkdf2 else PB_FALSE)
                      + pb_iter_str.encode('ascii'))

        compressed_path = None
        cipher_path = None
        try:
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
            cipher_key, mac_key = self._derive_keys(
                self.password, salt, cipher_len, self.pbkdf2_iter
            )

            # 3. 构建头部（含 pb 段）并初始化 HMAC
            header_prefix = MAGIC + mode_flag + algo_byte + pb_segment + salt + nonce
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
        finally:
            # 清理临时文件：无论成功失败都尝试安全删除
            secure_delete(compressed_path)
            secure_delete(cipher_path)

    def decrypt_stream(self, input_path: str, output_path: str,
                       ignore_magic: bool = False, user_password: str = None):
        """
        解密文件。
        [P0-2 改进] 流式字符读取，避免大文件一次性读入内存 OOM。
        [P1-A3 改进] 自动识别旧版(无pb)/新版(含pb)头部，读取自定义迭代次数。
        """
        decoded_path = None
        plain_path = None
        try:
            # ============================================================
            # 阶段 1：流式字符解码（不再 fin.read() 整个文件）
            # ============================================================
            decoder = None
            mode = None
            first_char_read = False

            with tempfile.NamedTemporaryFile(delete=False) as decoded_temp:
                decoded_path = decoded_temp.name

                with open(input_path, 'r', encoding='utf-8') as fin:
                    while True:
                        char_chunk = fin.read(CHAR_CHUNK)   # 128K 字符/次
                        if not char_chunk:
                            break
                        # 首块：按第一个字符判断编码模式 + 实例化 decoder
                        if not first_char_read:
                            if not char_chunk:
                                raise EncryptorError('文件内容为空')
                            first_ch = char_chunk[0]
                            code = ord(first_ch)
                            if ZC_START <= code < ZC_START + ZC_BASE:
                                decoder = ZcStreamDecoder()
                                mode = 'zc'
                            elif ZH_START <= code < ZH_START + ZH_BASE:
                                decoder = ZhStreamDecoder()
                                mode = 'zh'
                            else:
                                raise EncryptorError(
                                    f'无法识别的编码模式，首字符 U+{code:04X}')
                            first_char_read = True
                        # 解码并写入
                        binary_chunk = decoder.feed(char_chunk)
                        if binary_chunk:
                            decoded_temp.write(binary_chunk)
                    # 结束时 flush decoder
                    if decoder is None:
                        raise EncryptorError('文件内容为空')
                    remaining = decoder.flush()
                    if remaining:
                        decoded_temp.write(remaining)
                decoded_temp.flush()

            # ============================================================
            # 阶段 2：解析头部（兼容 v10 旧版 / v11 原版无pb / v11.1 含pb）
            # ============================================================
            with open(decoded_path, 'rb') as cipher_file:
                # 先读 4+2+1 = 7 字节，确认前导公共部分
                first_7 = cipher_file.read(7)
                if len(first_7) < 7:
                    raise EncryptorError('文件过短，无法读取头部前缀')
                cipher_file.seek(0)

                magic = first_7[:4]
                mode_flag = first_7[4:6]
                maybe_algo = first_7[6:7]

                # 判断新旧算法标识分支
                algo_byte_in_header = maybe_algo if maybe_algo in VALID_ALGOS else None

                # 预读 algo_byte 后 2 字节判断是否有 pb 段
                # 先定位到"算法标识之后"的位置
                if algo_byte_in_header is not None:
                    # 新版算法标识：下一个位置 = 7 字节处
                    algo_start_offset = 7
                else:
                    # 旧版 v10（无算法标识）：第7字节是 salt 的首字节
                    algo_start_offset = 6

                # 读 "算法标识之后" 的 2 字节判断是不是 PB_FLAG
                cipher_file.seek(algo_start_offset)
                pb_check_2 = cipher_file.read(2)

                # 组装 header_size 等信息
                use_pbkdf2_iter = PBKDF2_ITER_DEFAULT   # 默认
                if pb_check_2 == PB_FLAG:
                    # ===== v11.1 含 pb 扩展格式 =====
                    # 读取 pb 段剩余：T/F (1B) + 8 位数字 (8B)
                    pb_rest = cipher_file.read(1 + PB_NUM_LEN)
                    if len(pb_rest) != 1 + PB_NUM_LEN:
                        raise EncryptorError('头部 pb 段不完整')
                    pb_tf_byte = bytes([pb_rest[0]])
                    pb_num_str = pb_rest[1:1 + PB_NUM_LEN].decode('ascii')
                    # 解析 8 位数字
                    if not pb_num_str.isdigit():
                        raise EncryptorError(f'pb 迭代次数字段非法: {pb_num_str!r}')
                    pb_iter_value = int(pb_num_str)
                    # 只有 pb=T 才用自定义，否则强制默认
                    if pb_tf_byte == PB_TRUE:
                        use_pbkdf2_iter = pb_iter_value
                    elif pb_tf_byte == PB_FALSE:
                        use_pbkdf2_iter = PBKDF2_ITER_DEFAULT
                    else:
                        raise EncryptorError(f'pb T/F 字段非法: {pb_tf_byte!r}')
                    # pb 段总长 11B，盐在 algo_start_offset + 11 之后
                    salt_offset = algo_start_offset + len(PB_FLAG) + 1 + PB_NUM_LEN
                    header_size = salt_offset + SALT_LEN + NONCE_LEN + SIG_LEN
                else:
                    # ===== 旧 v10 / v11 原版无 pb =====
                    # pb 段跳过，迭代用默认
                    salt_offset = algo_start_offset
                    if algo_byte_in_header is not None:
                        # v11 原版（有 algo，无 pb）
                        header_size = salt_offset + SALT_LEN + NONCE_LEN + SIG_LEN
                    else:
                        # v10 原版（无 algo，无 pb）
                        header_size = salt_offset + SALT_LEN + NONCE_LEN + SIG_LEN

                # 实际读完整头部，按 header_size 一次性拉
                cipher_file.seek(0)
                header_data = cipher_file.read(header_size)
                if len(header_data) < header_size:
                    raise EncryptorError('文件过短，无法读取完整头部')

                # 再按上面判断的字段切片
                magic_read = header_data[:4]
                mode_flag_read = header_data[4:6]
                if algo_byte_in_header is not None:
                    algo_byte_read = header_data[6:7]
                else:
                    algo_byte_read = ALGO_SHA

                salt_read = header_data[salt_offset: salt_offset + SALT_LEN]
                nonce_read = header_data[salt_offset + SALT_LEN:
                                         salt_offset + SALT_LEN + NONCE_LEN]
                sig_offset = salt_offset + SALT_LEN + NONCE_LEN
                stored_sig = header_data[sig_offset: sig_offset + SIG_LEN]
                # header_prefix 是去掉末尾 SIG_LEN 的全部
                header_prefix = header_data[:sig_offset]

                # 合法性校验
                if not ignore_magic and magic_read != MAGIC:
                    raise EncryptorError('魔术头不匹配 (文件可能被篡改或非本工具加密)')
                if mode_flag_read not in (MODE_ZC, MODE_ZH):
                    raise EncryptorError(f'不支持的格式标志: {mode_flag_read}')
                if algo_byte_read not in VALID_ALGOS:
                    raise EncryptorError(f'不支持的算法标识: {algo_byte_read}')

                if user_password is None:
                    raise EncryptorError('解密需要提供密码')
                password_bytes = user_password.encode('utf-8')

                cipher_len = self._cipher_len_for_algo(algo_byte_read)
                cipher_key, mac_key = self._derive_keys(
                    password_bytes, salt_read, cipher_len, use_pbkdf2_iter
                )

                # 验证 HMAC
                mac = hmac.new(mac_key, digestmod=hashlib.sha256)
                mac.update(header_prefix)

                # 解密
                with tempfile.NamedTemporaryFile(delete=False) as plain_temp:
                    plain_path = plain_temp.name
                    block_counter = 0
                    cipher_obj = None
                    if algo_byte_read in (ALGO_AES, ALGO_CHACHA):
                        cipher_obj = self._create_cipher(
                            algo_byte_read, cipher_key, nonce_read
                        )

                    while True:
                        encrypted_block = cipher_file.read(CHUNK_SIZE)
                        if not encrypted_block:
                            break
                        mac.update(encrypted_block)
                        decrypted_block, block_counter, cipher_obj = self._encrypt_block(
                            algo_byte_read, cipher_key, nonce_read,
                            block_counter, encrypted_block, cipher_obj
                        )
                        plain_temp.write(decrypted_block)

                    computed_sig = mac.digest()
                    if not ignore_magic:
                        if not hmac.compare_digest(stored_sig, computed_sig):
                            # 签名失败：先关句柄再安全删，避免 Windows 文件锁
                            try:
                                plain_temp.close()
                            except Exception:
                                pass
                            secure_delete(plain_path)
                            plain_path = None
                            raise EncryptorError(
                                '签名验证失败 (文件完整性受损或密码错误)'
                            )
                    plain_temp.flush()

                # 解压缩
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
        finally:
            secure_delete(decoded_path)
            secure_delete(plain_path)


# ******************** 便捷函数 ********************
def encrypt_file(input_path: str, output_path: str, password: str,
                 mode: str = 'zh', algo: str = None,
                 pbkdf2_iter: int = None):
    Encryptor(password, algo, pbkdf2_iter).encrypt_stream(
        input_path, output_path, mode
    )

def decrypt_file(input_path: str, output_path: str, password: str = None,
                 ignore_magic: bool = False):
    Encryptor().decrypt_stream(input_path, output_path, ignore_magic,
                                user_password=password)


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
            self.root.title('Unicode 加密工具 v11.1 (多算法 + PBKDF2 可调)')
            self.root.resizable(False, False)

            self.mode = tk.StringVar(value='encrypt')
            self.enc_mode = tk.StringVar(value='zh')
            # 默认算法与命令行一致：智能探测（AES优先，未装pycryptodome则SHA）
            default_algo_display = 'AES-128-CTR' if DEFAULT_ALGO == 'a' else 'SHA256 (零依赖)'
            self.algo = tk.StringVar(value=default_algo_display)
            self.input_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.password = tk.StringVar()
            # PBKDF2 iter GUI 字段
            self.pbkdf2_iter = tk.StringVar(value=str(PBKDF2_ITER_DEFAULT))

            self.create_widgets()

        def create_widgets(self):
            # ============================================================
            # 【重要】主界面严格保持原版 3 列布局，防止 Pydroid3 手机端横向溢出：
            #   col0 = 标签 (宽度小)
            #   col1 = 输入框 (width=50, 与原版一致)
            #   col2 = 浏览按钮 / 执行按钮
            # 额外功能（编码、算法、PBKDF2）全部塞进 mode_frame 内部，不改变主结构。
            # ============================================================
            mode_frame = ttk.LabelFrame(self.root, text='操作模式', padding=5)
            mode_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5, sticky='ew')

            # ---------- mode_frame 第 0 行：加密/解密 + 编码模式 + 加密算法 ----------
            ttk.Radiobutton(mode_frame, text='加密', variable=self.mode,
                            value='encrypt', command=self.update_mode).grid(
                                row=0, column=0, padx=5, pady=2, sticky='w')
            ttk.Radiobutton(mode_frame, text='解密', variable=self.mode,
                            value='decrypt', command=self.update_mode).grid(
                                row=0, column=1, padx=5, pady=2, sticky='w')

            self.enc_mode_label = ttk.Label(mode_frame, text='编码模式:')
            self.enc_mode_label.grid(row=0, column=2, padx=(10, 3), pady=2, sticky='w')
            self.enc_mode_combo = ttk.Combobox(mode_frame, textvariable=self.enc_mode,
                                               values=['zh (汉字编码)', 'zc (Base-112)'],
                                               state='readonly', width=14)
            self.enc_mode_combo.grid(row=0, column=3, padx=3, pady=2, sticky='w')
            self.enc_mode_combo.bind('<<ComboboxSelected>>', self.on_enc_mode_change)

            self.algo_label = ttk.Label(mode_frame, text='加密算法:')
            self.algo_label.grid(row=0, column=4, padx=(10, 3), pady=2, sticky='w')
            algo_values = ['SHA256 (零依赖)', 'AES-128-CTR', 'ChaCha20']
            self.algo_combo = ttk.Combobox(mode_frame, textvariable=self.algo,
                                           values=algo_values, state='readonly', width=14)
            self.algo_combo.grid(row=0, column=5, padx=3, pady=2, sticky='w')
            self.algo_combo.bind('<<ComboboxSelected>>', self.on_algo_change)

            # ---------- mode_frame 第 1 行：PBKDF2 迭代次数（新增功能，不占主界面3列）----------
            self.pbkdf2_label = ttk.Label(
                mode_frame,
                text='迭代次数 N:'
            )
            self.pbkdf2_label.grid(row=1, column=0, padx=5, pady=(3, 2), sticky='w')
            self.pbkdf2_entry = ttk.Entry(
                mode_frame, textvariable=self.pbkdf2_iter, width=16
            )
            self.pbkdf2_entry.grid(row=1, column=1, padx=3, pady=(3, 2), sticky='w')
            self.pbkdf2_hint = ttk.Label(
                mode_frame,
                text=('默认60w，推荐10w~500w'
                      '解密端自动读取。'),
                foreground='#666666'
            )
            self.pbkdf2_hint.grid(row=1, column=2, columnspan=4, padx=5, pady=(3, 2), sticky='w')

            # ---------- 主界面 row 1/2/3：输入文件 / 输出文件 / 密码（严格与原版一致）----------
            tk.Label(self.root, text='输入文件:').grid(
                row=1, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.input_path, width=50).grid(
                row=1, column=1, padx=5, pady=5)
            tk.Button(self.root, text='浏览...', command=self.browse_input).grid(
                row=1, column=2, padx=5, pady=5)

            tk.Label(self.root, text='输出文件:').grid(
                row=2, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.output_path, width=50).grid(
                row=2, column=1, padx=5, pady=5)
            tk.Button(self.root, text='浏览...', command=self.browse_output).grid(
                row=2, column=2, padx=5, pady=5)

            tk.Label(self.root, text='密码:').grid(
                row=3, column=0, padx=5, pady=5, sticky='w')
            tk.Entry(self.root, textvariable=self.password, width=50, show='*').grid(
                row=3, column=1, padx=5, pady=5)

            self.run_button = tk.Button(self.root, text='执行', command=self.run,
                                        width=12, height=1)
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
                    import Crypto  # noqa: F401
                except ImportError:
                    messagebox.showwarning(
                        '缺失依赖',
                        f'您选择了 {algo}，但未安装 pycryptodome。\n'
                        '请运行: pip install pycryptodome\n'
                        '或切换回 SHA256 (零依赖) 模式。'
                    )
                    # 自动切到当前 DEFAULT_ALGO（智能探测后的合法默认）
                    fallback = 'SHA256 (零依赖)' if DEFAULT_ALGO == 's' else 'AES-128-CTR'
                    self.algo.set(fallback)

        def update_mode(self):
            if self.mode.get() == 'encrypt':
                # 加密：编码/算法/PBKDF2 全部显示
                self.enc_mode_label.grid()
                self.enc_mode_combo.grid()
                self.algo_label.grid()
                self.algo_combo.grid()
                # PBKDF2 的三个控件都在 mode_frame 内部，单独显示
                self.pbkdf2_label.grid()
                self.pbkdf2_entry.grid()
                self.pbkdf2_hint.grid()
            else:
                # 解密：隐藏编码、算法、PBKDF2 输入（PBKDF2 头自带，解密端自动读）
                self.enc_mode_label.grid_remove()
                self.enc_mode_combo.grid_remove()
                self.algo_label.grid_remove()
                self.algo_combo.grid_remove()
                # PBKDF2 三控件单独隐藏（不能再 hide master，master 是 mode_frame）
                self.pbkdf2_label.grid_remove()
                self.pbkdf2_entry.grid_remove()
                self.pbkdf2_hint.grid_remove()
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

        # ---- PBKDF2 GUI 校验：解析 + <600000 二次确认 ----
        def _validate_and_get_pbkdf2_iter(self) -> int | None:
            """
            验证并返回加密用的 PBKDF2 迭代次数。
              - None 表示"用户取消操作，不继续加密"
              - int  表示确认后的次数
            <600000 时弹 askyesno 警告，确定→返回该值，取消→返回 None。
            """
            raw = self.pbkdf2_iter.get().strip()
            if not raw.isdigit():
                messagebox.showerror(
                    '参数错误',
                    'PBKDF2 迭代次数必须是正整数（不含小数点、字母、空格）。'
                )
                return None
            val = int(raw)
            if val < 1000:
                messagebox.showerror(
                    '参数错误',
                    'PBKDF2 迭代次数不得低于 1000，否则几乎没有抗暴力破解能力。'
                )
                return None
            if val > 99_999_999:
                messagebox.showerror(
                    '参数错误',
                    'PBKDF2 迭代次数不得超过 99999999（超过文件头部 8 位数字容量）。'
                )
                return None
            if val < PBKDF2_ITER_DEFAULT:
                # 用户定制：低于默认 60 万 → 弹警告，确认再继续，取消则什么也不做
                proceed = messagebox.askyesno(
                    '安全性可能不足',
                    f'您设置的 PBKDF2 迭代次数为 {val}，\n'
                    f'低于推荐默认值 {PBKDF2_ITER_DEFAULT}，\n'
                    '抗 GPU / ASIC 暴力破解的能力将显著下降。\n\n'
                    '是否仍然使用该次数继续加密？\n\n'
                    '  [是] 使用您输入的次数继续\n'
                    '  [否] 返回修改参数（什么也不做）'
                )
                if not proceed:
                    return None   # 用户取消：什么也不做
            return val

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
                    # ---- 加密分支 ----
                    if not self.password.get():
                        messagebox.showerror('错误', '加密需要输入密码')
                        return

                    # [PBKDF2] 校验 & 可选二次确认
                    iter_value = self._validate_and_get_pbkdf2_iter()
                    if iter_value is None:
                        # 用户取消（如 <60w 点了"否"），什么也不做，恢复"就绪"
                        self.status.config(text='就绪（用户已取消）')
                        self.root.update()
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
                        algo = None
                    if algo in ('a', 'c'):
                        try:
                            import Crypto  # noqa: F401
                        except ImportError:
                            raise EncryptorError(
                                f'算法 {algo_str} 需要 pycryptodome，'
                                '请安装: pip install pycryptodome'
                            )
                    encrypt_file(self.input_path.get(), self.output_path.get(),
                                 self.password.get(),
                                 mode=enc_mode, algo=algo,
                                 pbkdf2_iter=iter_value)
                    if iter_value == PBKDF2_ITER_DEFAULT:
                        tag = 'pb=F(默认600000)'
                    else:
                        tag = f'pb=T({iter_value})'
                    msg = (f"加密完成（{algo.upper()}算法，{enc_mode.upper()}编码，"
                           f"{tag}）！\n输出文件：{self.output_path.get()}")
                else:
                    # ---- 解密分支 ----
                    pwd = self.password.get() if self.password.get() else None
                    try:
                        decrypt_file(self.input_path.get(), self.output_path.get(),
                                     password=pwd)
                        msg = f"解密完成！\n输出文件：{self.output_path.get()}"
                    except EncryptorError as e:
                        if '魔术头不匹配' in str(e):
                            retry = messagebox.askyesno(
                                '魔术头不匹配',
                                '文件的魔术头不匹配，可能是旧版本文件。\n'
                                '是否尝试忽略魔术头并继续？'
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
    parser = argparse.ArgumentParser(
        description='Unicode加密工具 v11.1（多算法 + PBKDF2迭代可调）'
    )
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('mode', nargs='?', choices=['encrypt', 'decrypt'],
                        help='操作模式')
    parser.add_argument('input', nargs='?', help='输入文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径（默认自动生成）')
    parser.add_argument('-p', '--password', help='密码')
    parser.add_argument('--enc-mode', choices=['zc', 'zh'], default='zh',
                        help='编码模式：zc (Base-112) 或 zh (汉字编码，默认)')
    parser.add_argument('--algo', choices=['s', 'a', 'c'], default=None,
                        help=('加密算法：s=SHA256(零依赖), a=AES-128-CTR(默认优先,需pycryptodome), '
                              'c=ChaCha20(需pycryptodome)。不填则智能探测：'
                              '已装pycryptodome→a，未装→s'))
    parser.add_argument('--ignore-magic', action='store_true',
                        help='忽略魔术头校验（用于解密旧版本文件）')
    parser.add_argument('--iter', type=int, default=None, metavar='N',
                        help=('【加密时】自定义 PBKDF2 迭代次数 N（整数，>=1000，<=99999999）。'
                              '不传则使用默认 600000 并写入头部 pb=F；'
                              f'传入则写入头部 pb=T + %08d 数字，解密自动读取。'
                              f'推荐范围 100000~5000000，N<600000 将打印风险警告。'))
    args = parser.parse_args()

    if args.gui or (args.mode is None and args.input is None):
        gui_main()
        return

    if args.mode is None or args.input is None:
        parser.error('命令行模式需要指定 mode 和 input')

    if not os.path.isfile(args.input):
        print(f"错误：文件 {args.input} 不存在")
        return

    # 算法智能选默认值 + 选 a/c 时校验依赖
    chosen_algo = args.algo if args.algo is not None else DEFAULT_ALGO
    if chosen_algo in ('a', 'c'):
        try:
            import Crypto  # noqa: F401
        except ImportError:
            print(f"错误：算法 {chosen_algo} 需要 pycryptodome，"
                  f"请安装: pip install pycryptodome")
            return

    # PBKDF2 --iter 参数处理
    pbkdf2_iter_val = None
    if args.mode == 'encrypt' and args.iter is not None:
        N = args.iter
        if not isinstance(N, int) or N < 1000:
            print(f"错误：--iter 必须为 >=1000 的整数，收到: {N!r}")
            return
        if N > 99_999_999:
            print(f"错误：--iter 最大支持 99999999，收到: {N}")
            return
        if N < PBKDF2_ITER_DEFAULT:
            print(f"[警告] --iter={N} 低于推荐默认值 {PBKDF2_ITER_DEFAULT}，"
                  "抗暴力破解能力下降。")
        pbkdf2_iter_val = N

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
                         mode=args.enc_mode, algo=chosen_algo,
                         pbkdf2_iter=pbkdf2_iter_val)
            pb_tag = (f"pb=T({pbkdf2_iter_val})"
                      if pbkdf2_iter_val is not None
                      else f"pb=F(默认{PBKDF2_ITER_DEFAULT})")
            print(f"加密完成（{chosen_algo.upper()}算法，{args.enc_mode.upper()}编码，"
                  f"{pb_tag}），输出文件: {output_path}")
        else:
            decrypt_file(args.input, output_path, password=password,
                         ignore_magic=args.ignore_magic)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")


if __name__ == '__main__':
    cli_main()
