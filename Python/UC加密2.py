import os
import zlib
import hashlib
import hmac
from math import ceil
from getpass import getpass

# Unicode 范围：U+0300 到 U+036F（共 112 个字符）
BASE = 112
START = 0x0300
MAGIC = b'UC02'  # 魔术头，标识文件格式版本 2.0

def to_chars(data: bytes) -> str:
    """将字节数据编码为由 U+0300..U+036F 组成的字符串"""
    chars = []
    for b in data:
        high = b // BASE
        low = b % BASE
        chars.append(chr(START + high))
        chars.append(chr(START + low))
    return ''.join(chars)

def from_chars(s: str) -> bytes:
    """将 U+0300..U+036F 字符串解码回字节数据"""
    if len(s) % 2 != 0:
        raise ValueError("编码字符串长度必须为偶数")
    data = bytearray()
    for i in range(0, len(s), 2):
        c1 = ord(s[i]) - START
        c2 = ord(s[i+1]) - START
        if not (0 <= c1 < BASE and 0 <= c2 < BASE):
            raise ValueError("发现范围外的字符")
        data.append(c1 * BASE + c2)
    return bytes(data)

def encrypt_file(input_path: str, output_path: str, password: str, compress: bool):
    """加密文件（可选压缩），输出格式：MAGIC(4) + flag(1) + salt(16) + nonce(12) + signature(32) + ciphertext"""
    # 1. 读取原始数据
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # 2. 根据选项决定是否压缩
    if compress:
        compressed = zlib.compress(plaintext)
        flag = b'\x01'
        data_to_encrypt = compressed
    else:
        flag = b'\x00'
        data_to_encrypt = plaintext

    # 3. 生成随机 salt 和 nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # 4. 派生密钥（PBKDF2）
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    enc_key = key[:16]
    mac_key = key[16:]

    # 5. 加密（流模式，基于 HMAC-SHA256 的计数器）
    ciphertext = bytearray()
    block_size = 32  # HMAC 输出长度
    num_blocks = ceil(len(data_to_encrypt) / block_size)
    for i in range(num_blocks):
        counter = i.to_bytes(4, 'big')
        prf_input = nonce + counter
        keystream = hmac.new(enc_key, prf_input, hashlib.sha256).digest()
        block = data_to_encrypt[i*block_size : (i+1)*block_size]
        for j in range(len(block)):
            ciphertext.append(block[j] ^ keystream[j])
    ciphertext = bytes(ciphertext)

    # 6. 计算 HMAC 签名（对密文）
    signature = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()

    # 7. 打包：MAGIC(4) + flag(1) + salt(16) + nonce(12) + signature(32) + ciphertext
    packed = MAGIC + flag + salt + nonce + signature + ciphertext

    # 8. 编码为特殊字符并写入文件
    encoded = to_chars(packed)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(encoded)

def decrypt_file(input_path: str, output_path: str, password: str):
    """解密文件（自动检测压缩标志并解压）"""
    # 1. 读取编码数据
    with open(input_path, 'r', encoding='utf-8') as f:
        encoded = f.read().strip()

    # 2. 解码
    packed = from_chars(encoded)

    # 3. 检查魔术头
    if len(packed) < len(MAGIC):
        raise ValueError("文件太短，不是有效的加密文件")
    if packed[:len(MAGIC)] != MAGIC:
        raise ValueError("魔术头不匹配，不是本程序生成的加密文件")

    # 4. 提取各部分（跳过魔术头）
    offset = len(MAGIC)
    flag = packed[offset:offset+1]
    salt = packed[offset+1:offset+17]          # 16 字节
    nonce = packed[offset+17:offset+29]        # 12 字节
    signature = packed[offset+29:offset+61]     # 32 字节
    ciphertext = packed[offset+61:]

    # 5. 派生密钥
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    enc_key = key[:16]
    mac_key = key[16:]

    # 6. 验证签名
    expected_sig = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("签名验证失败！数据可能被篡改或密码错误。")

    # 7. 解密
    plain_compressed = bytearray()
    block_size = 32
    num_blocks = ceil(len(ciphertext) / block_size)
    for i in range(num_blocks):
        counter = i.to_bytes(4, 'big')
        prf_input = nonce + counter
        keystream = hmac.new(enc_key, prf_input, hashlib.sha256).digest()
        block = ciphertext[i*block_size : (i+1)*block_size]
        for j in range(len(block)):
            plain_compressed.append(block[j] ^ keystream[j])
    plain_compressed = bytes(plain_compressed)

    # 8. 根据标志决定是否解压
    if flag == b'\x01':
        plaintext = zlib.decompress(plain_compressed)
    elif flag == b'\x00':
        plaintext = plain_compressed
    else:
        raise ValueError("未知的压缩标志")

    # 9. 写入解密后的文件
    with open(output_path, 'wb') as f:
        f.write(plaintext)

def main():
    path = input("请输入文件路径: ").strip()
    if not os.path.isfile(path):
        print("文件不存在！")
        return

    mode = input("请选择模式：加密(e) 或 解密(d): ").strip().lower()
    if mode not in ('e', 'd'):
        print("无效模式！")
        return

    password = getpass("请输入密码: ")

    compress = False
    if mode == 'e':
        comp_choice = input("是否启用压缩（可减小体积）？(y/n，默认n): ").strip().lower()
        compress = (comp_choice == 'y')

    # 生成输出文件名
    dir_name = os.path.dirname(path)
    base_name = os.path.basename(path)
    if mode == 'e':
        output_name = base_name + "-enc"
    else:  # 解密
        if base_name.endswith("-enc"):
            output_name = base_name[:-4] + "-dec"
        else:
            output_name = base_name + "-dec"
    output_path = os.path.join(dir_name, output_name)

    try:
        if mode == 'e':
            encrypt_file(path, output_path, password, compress)
            comp_info = "（已压缩）" if compress else "（未压缩）"
            print(f"加密完成，输出文件: {output_path} {comp_info}")
        else:
            decrypt_file(path, output_path, password)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")

if __name__ == "__main__":
    main()