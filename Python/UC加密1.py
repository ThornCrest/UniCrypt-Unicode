import os
import hashlib
import hmac
from math import ceil
from getpass import getpass

# Unicode 范围：U+0300 到 U+036F (共 112 个字符)
BASE = 112
START = 0x0300

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

def encrypt_file(input_path: str, output_path: str, password: str):
    """加密文件：派生密钥 -> 流加密 -> HMAC 签名 -> 编码为特殊字符 -> 写入文件"""
    # 读取原始数据
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # 生成随机 salt 和 nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # 使用 PBKDF2 派生 32 字节密钥（前16字节加密，后16字节认证）
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    enc_key = key[:16]
    mac_key = key[16:]

    # 加密：计数器模式，以 HMAC-SHA256 作为伪随机函数
    ciphertext = bytearray()
    block_size = 32  # HMAC 输出长度
    num_blocks = ceil(len(plaintext) / block_size)
    for i in range(num_blocks):
        counter = i.to_bytes(4, 'big')
        prf_input = nonce + counter
        keystream = hmac.new(enc_key, prf_input, hashlib.sha256).digest()
        block = plaintext[i*block_size : (i+1)*block_size]
        for j in range(len(block)):
            ciphertext.append(block[j] ^ keystream[j])
    ciphertext = bytes(ciphertext)

    # 计算 HMAC 签名
    signature = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()

    # 组装数据：salt(16) + nonce(12) + signature(32) + ciphertext
    packed = salt + nonce + signature + ciphertext

    # 编码为特殊字符并写入文件
    encoded = to_chars(packed)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(encoded)

def decrypt_file(input_path: str, output_path: str, password: str):
    """解密文件：读取特殊字符 -> 解码 -> 验证签名 -> 解密 -> 写入文件"""
    # 读取编码数据
    with open(input_path, 'r', encoding='utf-8') as f:
        encoded = f.read().strip()

    # 解码
    packed = from_chars(encoded)

    # 提取各部分
    salt = packed[:16]
    nonce = packed[16:28]      # 12 字节
    signature = packed[28:60]   # 32 字节
    ciphertext = packed[60:]

    # 派生密钥
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    enc_key = key[:16]
    mac_key = key[16:]

    # 验证签名
    expected_sig = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("签名验证失败！数据可能被篡改或密码错误。")

    # 解密（与加密相同流程）
    plaintext = bytearray()
    block_size = 32
    num_blocks = ceil(len(ciphertext) / block_size)
    for i in range(num_blocks):
        counter = i.to_bytes(4, 'big')
        prf_input = nonce + counter
        keystream = hmac.new(enc_key, prf_input, hashlib.sha256).digest()
        block = ciphertext[i*block_size : (i+1)*block_size]
        for j in range(len(block)):
            plaintext.append(block[j] ^ keystream[j])

    # 写入解密后的文件
    with open(output_path, 'wb') as f:
        f.write(bytes(plaintext))

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

    # 生成输出文件名
    dir_name = os.path.dirname(path)
    base_name = os.path.basename(path)
    if mode == 'e':
        output_name = base_name + "-enc"
    else:  # 解密
        # 如果输入文件名以 -enc 结尾，则替换为 -dec，否则直接添加
        if base_name.endswith("-enc"):
            output_name = base_name[:-4] + "-dec"
        else:
            output_name = base_name + "-dec"
    output_path = os.path.join(dir_name, output_name)

    try:
        if mode == 'e':
            encrypt_file(path, output_path, password)
            print(f"加密完成，输出文件: {output_path}")
        else:
            decrypt_file(path, output_path, password)
            print(f"解密完成，输出文件: {output_path}")
    except Exception as e:
        print(f"操作失败: {e}")

if __name__ == "__main__":
    main()