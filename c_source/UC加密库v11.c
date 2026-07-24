#include "unicrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <zlib.h>
#include <fcntl.h>
#include <unistd.h>

/* ---------- 常量 ---------- */
#define MAGIC           "UC11"          /* 与Python版本一致 */
#define MAGIC_LEN       4
#define SALT_LEN        16
#define NONCE_LEN       12
#define SIG_LEN         32
#define PBKDF2_ITER     600000
#define CHUNK_SIZE      65536

#define MODE_ZC         "zc"
#define MODE_ZH         "zh"

#define ZC_BASE         112
#define ZC_START        0x0300
#define ZH_BASE         256
#define ZH_START        0x4E00

/* 算法标识长度 */
#define ALGO_LEN        1

/* 头部结构（新格式）：MAGIC(4) + MODE(2) + ALGO(1) + SALT(16) + NONCE(12) + SIG(32) */
#define HEADER_NO_SIG_LEN (MAGIC_LEN + 2 + ALGO_LEN + SALT_LEN + NONCE_LEN)
#define HEADER_FULL_LEN   (HEADER_NO_SIG_LEN + SIG_LEN)

/* ---------- 错误描述 ---------- */
const char* unicrypto_strerror(unicrypto_error_t err) {
    switch(err) {
        case UNICRYPTO_OK: return "成功";
        case UNICRYPTO_ERR_IO: return "I/O错误";
        case UNICRYPTO_ERR_MEM: return "内存不足";
        case UNICRYPTO_ERR_FORMAT: return "文件格式错误";
        case UNICRYPTO_ERR_HMAC: return "HMAC验证失败";
        case UNICRYPTO_ERR_DECOMPRESS: return "解压失败";
        case UNICRYPTO_ERR_RANDOM: return "随机数生成失败";
        case UNICRYPTO_ERR_UNSUPPORTED: return "不支持的编码模式或算法";
        default: return "未知错误";
    }
}

/* ============================================================
 *  SHA-256 实现（完全自包含）
 * ============================================================ */
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(sha256_ctx *ctx) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t W[64];
    int i;
    for (i = 0; i < 16; i++) {
        W[i] = (ctx->buffer[i*4] << 24) | (ctx->buffer[i*4+1] << 16) |
               (ctx->buffer[i*4+2] << 8) | ctx->buffer[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ((W[i-15] >> 7) | (W[i-15] << 25)) ^
                      ((W[i-15] >> 18) | (W[i-15] << 14)) ^
                      (W[i-15] >> 3);
        uint32_t s1 = ((W[i-2] >> 17) | (W[i-2] << 15)) ^
                      ((W[i-2] >> 19) | (W[i-2] << 13)) ^
                      (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ((e >> 6) | (e << 26)) ^
                      ((e >> 11) | (e << 21)) ^
                      ((e >> 25) | (e << 7));
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = ((a >> 2) | (a << 30)) ^
                      ((a >> 13) | (a << 19)) ^
                      ((a >> 22) | (a << 10));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = data[i];
        ctx->count++;
        if (ctx->count % SHA256_BLOCK_SIZE == 0) {
            sha256_transform(ctx);
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char *digest) {
    uint64_t bit_len = ctx->count * 8;
    unsigned char pad[64];
    int pad_len = (ctx->count % SHA256_BLOCK_SIZE < 56) ? (56 - ctx->count % SHA256_BLOCK_SIZE) : (120 - ctx->count % SHA256_BLOCK_SIZE);
    pad[0] = 0x80;
    for (int i = 1; i < pad_len; i++) pad[i] = 0;
    sha256_update(ctx, pad, pad_len);
    unsigned char len_buf[8];
    for (int i = 0; i < 8; i++) len_buf[7-i] = (bit_len >> (i*8)) & 0xFF;
    sha256_update(ctx, len_buf, 8);
    for (int i = 0; i < 8; i++) {
        digest[i*4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4+3] = ctx->state[i] & 0xFF;
    }
}

/* ============================================================
 *  HMAC-SHA256 工具
 * ============================================================ */
static void hmac_sha256(const unsigned char *key, size_t key_len,
                        const unsigned char *msg, size_t msg_len,
                        unsigned char *out) {
    unsigned char k_ipad[SHA256_BLOCK_SIZE];
    unsigned char k_opad[SHA256_BLOCK_SIZE];
    unsigned char tk[SHA256_DIGEST_SIZE];
    size_t i;
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, tk);
        key = tk;
        key_len = SHA256_DIGEST_SIZE;
    }
    memset(k_ipad, 0, SHA256_BLOCK_SIZE);
    memset(k_opad, 0, SHA256_BLOCK_SIZE);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, msg, msg_len);
    unsigned char inner_hash[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, inner_hash);
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}

/* 增量 HMAC-SHA256（用于流式加密） */
typedef struct {
    sha256_ctx inner, outer;
} hmac_sha256_ctx;

static void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key, size_t key_len) {
    unsigned char k[SHA256_BLOCK_SIZE];
    memset(k, 0, SHA256_BLOCK_SIZE);
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_ctx tmp;
        sha256_init(&tmp);
        sha256_update(&tmp, key, key_len);
        sha256_final(&tmp, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k[i] ^= 0x36;
    }
    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, k, SHA256_BLOCK_SIZE);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k[i] ^= (0x36 ^ 0x5c);
    }
    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, k, SHA256_BLOCK_SIZE);
}

static void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *data, size_t len) {
    sha256_update(&ctx->inner, data, len);
}

static void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *out) {
    unsigned char inner_hash[SHA256_DIGEST_SIZE];
    sha256_final(&ctx->inner, inner_hash);
    sha256_update(&ctx->outer, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->outer, out);
}

/* ============================================================
 *  PBKDF2-HMAC-SHA256
 * ============================================================ */
static int pbkdf2_hmac_sha256(const unsigned char *pass, size_t pass_len,
                               const unsigned char *salt, size_t salt_len,
                               uint32_t iterations, size_t dklen,
                               unsigned char *out) {
    uint32_t block = 1;
    size_t written = 0;
    while (written < dklen) {
        unsigned char U[32], T[32];
        unsigned char block_buf[4];
        block_buf[0] = (block >> 24) & 0xFF;
        block_buf[1] = (block >> 16) & 0xFF;
        block_buf[2] = (block >> 8) & 0xFF;
        block_buf[3] = block & 0xFF;
        unsigned char msg[salt_len + 4];
        memcpy(msg, salt, salt_len);
        memcpy(msg + salt_len, block_buf, 4);
        hmac_sha256(pass, pass_len, msg, salt_len + 4, U);
        memcpy(T, U, 32);
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256(pass, pass_len, U, 32, U);
            for (int j = 0; j < 32; j++) T[j] ^= U[j];
        }
        size_t to_copy = (dklen - written) < 32 ? (dklen - written) : 32;
        memcpy(out + written, T, to_copy);
        written += to_copy;
        block++;
    }
    return 0;
}

/* ============================================================
 *  随机数生成
 * ============================================================ */
static int get_random_bytes(unsigned char *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return UNICRYPTO_ERR_RANDOM;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r <= 0) { close(fd); return UNICRYPTO_ERR_RANDOM; }
        got += r;
    }
    close(fd);
    return UNICRYPTO_OK;
}

/* ============================================================
 *  UTF-8 编解码（用于 Unicode 编码模式）
 * ============================================================ */
static int utf8_encode(uint32_t cp, unsigned char *out) {
    if (cp <= 0x7F) { out[0] = cp; return 1; }
    else if (cp <= 0x7FF) { out[0] = 0xC0 | ((cp >> 6) & 0x1F); out[1] = 0x80 | (cp & 0x3F); return 2; }
    else if (cp <= 0xFFFF) { out[0] = 0xE0 | ((cp >> 12) & 0x0F); out[1] = 0x80 | ((cp >> 6) & 0x3F); out[2] = 0x80 | (cp & 0x3F); return 3; }
    else if (cp <= 0x10FFFF) { out[0] = 0xF0 | ((cp >> 18) & 0x07); out[1] = 0x80 | ((cp >> 12) & 0x3F); out[2] = 0x80 | ((cp >> 6) & 0x3F); out[3] = 0x80 | (cp & 0x3F); return 4; }
    return -1;
}

static int utf8_decode(const unsigned char *buf, size_t len, uint32_t *cp) {
    if (len == 0) return -1;
    if (buf[0] <= 0x7F) { *cp = buf[0]; return 1; }
    else if ((buf[0] & 0xE0) == 0xC0) {
        if (len < 2) return -2;
        *cp = ((buf[0] & 0x1F) << 6) | (buf[1] & 0x3F);
        return 2;
    } else if ((buf[0] & 0xF0) == 0xE0) {
        if (len < 3) return -2;
        *cp = ((buf[0] & 0x0F) << 12) | ((buf[1] & 0x3F) << 6) | (buf[2] & 0x3F);
        return 3;
    } else if ((buf[0] & 0xF8) == 0xF0) {
        if (len < 4) return -2;
        *cp = ((buf[0] & 0x07) << 18) | ((buf[1] & 0x3F) << 12) | ((buf[2] & 0x3F) << 6) | (buf[3] & 0x3F);
        return 4;
    }
    return -1;
}

/* ============================================================
 *  ZC / ZH 编码器（批量，用于内存接口和解码）
 * ============================================================ */
static int encode_zc(const unsigned char *data, size_t len,
                     unsigned char **out, size_t *out_len) {
    size_t max_out = len * 2 * 3 + 1;
    unsigned char *buf = (unsigned char*)malloc(max_out);
    if (!buf) return UNICRYPTO_ERR_MEM;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        int high = data[i] / ZC_BASE;
        int low  = data[i] % ZC_BASE;
        int n1 = utf8_encode(ZC_START + high, buf + pos);
        int n2 = utf8_encode(ZC_START + low,  buf + pos + n1);
        if (n1 < 0 || n2 < 0) { free(buf); return UNICRYPTO_ERR_FORMAT; }
        pos += n1 + n2;
    }
    *out = buf;
    *out_len = pos;
    return UNICRYPTO_OK;
}

static int decode_zc(const unsigned char *utf8, size_t utf8_len,
                     unsigned char **out, size_t *out_len) {
    size_t chars = 0;
    size_t idx = 0;
    while (idx < utf8_len) {
        uint32_t cp;
        int n = utf8_decode(utf8 + idx, utf8_len - idx, &cp);
        if (n <= 0) return UNICRYPTO_ERR_FORMAT;
        idx += n;
        chars++;
    }
    if (chars % 2 != 0) return UNICRYPTO_ERR_FORMAT;
    unsigned char *buf = (unsigned char*)malloc(chars / 2);
    if (!buf) return UNICRYPTO_ERR_MEM;
    idx = 0; size_t out_pos = 0;
    while (idx < utf8_len) {
        uint32_t cp1, cp2;
        int n1 = utf8_decode(utf8 + idx, utf8_len - idx, &cp1); idx += n1;
        int n2 = utf8_decode(utf8 + idx, utf8_len - idx, &cp2); idx += n2;
        if (cp1 < ZC_START || cp1 >= ZC_START + ZC_BASE ||
            cp2 < ZC_START || cp2 >= ZC_START + ZC_BASE) {
            free(buf); return UNICRYPTO_ERR_FORMAT;
        }
        int high = cp1 - ZC_START;
        int low  = cp2 - ZC_START;
        buf[out_pos++] = (unsigned char)(high * ZC_BASE + low);
    }
    *out = buf;
    *out_len = out_pos;
    return UNICRYPTO_OK;
}

static int encode_zh(const unsigned char *data, size_t len,
                     unsigned char **out, size_t *out_len) {
    size_t max_out = len * 3 + 1;
    unsigned char *buf = (unsigned char*)malloc(max_out);
    if (!buf) return UNICRYPTO_ERR_MEM;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        int n = utf8_encode(ZH_START + data[i], buf + pos);
        if (n < 0) { free(buf); return UNICRYPTO_ERR_FORMAT; }
        pos += n;
    }
    *out = buf;
    *out_len = pos;
    return UNICRYPTO_OK;
}

static int decode_zh(const unsigned char *utf8, size_t utf8_len,
                     unsigned char **out, size_t *out_len) {
    unsigned char *buf = (unsigned char*)malloc(utf8_len);
    if (!buf) return UNICRYPTO_ERR_MEM;
    size_t idx = 0, out_pos = 0;
    while (idx < utf8_len) {
        uint32_t cp;
        int n = utf8_decode(utf8 + idx, utf8_len - idx, &cp);
        if (n <= 0) { free(buf); return UNICRYPTO_ERR_FORMAT; }
        idx += n;
        if (cp < ZH_START || cp >= ZH_START + ZH_BASE) {
            free(buf); return UNICRYPTO_ERR_FORMAT;
        }
        buf[out_pos++] = (unsigned char)(cp - ZH_START);
    }
    *out = buf;
    *out_len = out_pos;
    return UNICRYPTO_OK;
}

/* ============================================================
 *  流式编码器（直接写入 FILE*）
 * ============================================================ */
static int encode_zc_stream(FILE *out, const unsigned char *data, size_t len) {
    unsigned char buf[6];
    for (size_t i = 0; i < len; i++) {
        int high = data[i] / ZC_BASE;
        int low  = data[i] % ZC_BASE;
        int n1 = utf8_encode(ZC_START + high, buf);
        int n2 = utf8_encode(ZC_START + low,  buf + n1);
        if (fwrite(buf, 1, n1 + n2, out) != (size_t)(n1 + n2))
            return UNICRYPTO_ERR_IO;
    }
    return UNICRYPTO_OK;
}

static int encode_zh_stream(FILE *out, const unsigned char *data, size_t len) {
    unsigned char buf[3];
    for (size_t i = 0; i < len; i++) {
        int n = utf8_encode(ZH_START + data[i], buf);
        if (fwrite(buf, 1, n, out) != (size_t)n)
            return UNICRYPTO_ERR_IO;
    }
    return UNICRYPTO_OK;
}

/* ============================================================
 *  密钥派生（支持不同加密密钥长度）
 * ============================================================ */
static int derive_keys(const unsigned char *pass, size_t pass_len,
                       const unsigned char *salt, size_t salt_len,
                       size_t cipher_key_len,
                       unsigned char *cipher_key,
                       unsigned char *mac_key) {
    size_t total_len = cipher_key_len + 32;
    unsigned char *key_material = (unsigned char*)malloc(total_len);
    if (!key_material) return UNICRYPTO_ERR_MEM;
    if (pbkdf2_hmac_sha256(pass, pass_len, salt, salt_len, PBKDF2_ITER, total_len, key_material) != 0) {
        free(key_material);
        return UNICRYPTO_ERR_MEM;
    }
    memcpy(cipher_key, key_material, cipher_key_len);
    memcpy(mac_key, key_material + cipher_key_len, 32);
    free(key_material);
    return UNICRYPTO_OK;
}

/* ============================================================
 *  AES-128-CTR 纯 C 实现（tiny-AES 派生）
 * ============================================================ */
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

typedef struct {
    uint8_t roundKey[11 * 16];
} aes_ctx;

static void aes_key_expansion(const uint8_t *key, aes_ctx *ctx) {
    int i, j;
    uint8_t temp[4];
    uint8_t *roundKey = ctx->roundKey;
    for (i = 0; i < 16; i++) roundKey[i] = key[i];
    for (i = 16; i < 11 * 16; i += 4) {
        for (j = 0; j < 4; j++) temp[j] = roundKey[i - 4 + j];
        if (i % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            for (j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
            temp[0] ^= Rcon[i / 16];
        }
        for (j = 0; j < 4; j++) roundKey[i + j] = roundKey[i - 16 + j] ^ temp[j];
    }
}

static void aes_add_round_key(uint8_t *state, const uint8_t *roundKey) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

static void aes_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void aes_shift_rows(uint8_t *state) {
    uint8_t tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp; tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;
}

static uint8_t galois_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = (a & 0x80) ? (a << 1) ^ 0x1b : a << 1;
        b >>= 1;
    }
    return result;
}

static void aes_mix_columns(uint8_t *state) {
    uint8_t tmp[16];
    for (int i = 0; i < 4; i++) {
        int j = i * 4;
        uint8_t a0 = state[j], a1 = state[j+1], a2 = state[j+2], a3 = state[j+3];
        tmp[j]   = galois_mul(a0,2) ^ galois_mul(a1,3) ^ a2 ^ a3;
        tmp[j+1] = a0 ^ galois_mul(a1,2) ^ galois_mul(a2,3) ^ a3;
        tmp[j+2] = a0 ^ a1 ^ galois_mul(a2,2) ^ galois_mul(a3,3);
        tmp[j+3] = galois_mul(a0,3) ^ a1 ^ a2 ^ galois_mul(a3,2);
    }
    for (int i = 0; i < 16; i++) state[i] = tmp[i];
}

static void aes_encrypt_block(const aes_ctx *ctx, const uint8_t *in, uint8_t *out) {
    uint8_t state[16];
    for (int i = 0; i < 16; i++) state[i] = in[i];
    aes_add_round_key(state, ctx->roundKey);
    for (int round = 1; round < 10; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ctx->roundKey + round * 16);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, ctx->roundKey + 10 * 16);
    for (int i = 0; i < 16; i++) out[i] = state[i];
}

/* AES-CTR 加密/解密（同函数） */
static void aes_ctr_crypt(const unsigned char *key,
                          const unsigned char *nonce,
                          uint32_t *counter,
                          const unsigned char *in,
                          unsigned char *out,
                          size_t len) {
    aes_ctx ctx;
    aes_key_expansion(key, &ctx);
    unsigned char counter_block[16];
    unsigned char keystream[16];
    size_t processed = 0;
    while (processed < len) {
        // 构造 counter block: nonce (12 bytes) + counter (4 bytes big-endian)
        memcpy(counter_block, nonce, NONCE_LEN);
        counter_block[12] = (*counter >> 24) & 0xFF;
        counter_block[13] = (*counter >> 16) & 0xFF;
        counter_block[14] = (*counter >> 8) & 0xFF;
        counter_block[15] = (*counter) & 0xFF;
        aes_encrypt_block(&ctx, counter_block, keystream);
        (*counter)++;
        size_t block = (len - processed) < 16 ? (len - processed) : 16;
        for (size_t i = 0; i < block; i++) {
            out[processed + i] = in[processed + i] ^ keystream[i];
        }
        processed += block;
    }
}

/* ============================================================
 *  ChaCha20 纯 C 实现（RFC 7539）
 * ============================================================ */
#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_KEY_SIZE   32

static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}

static void chacha20_block(const unsigned char *key,
                           const unsigned char *nonce,
                           uint32_t counter,
                           unsigned char *keystream) {
    uint32_t state[16];
    const uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 4; i++) state[i] = constants[i];
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[4*i] << 0) |
                       ((uint32_t)key[4*i+1] << 8) |
                       ((uint32_t)key[4*i+2] << 16) |
                       ((uint32_t)key[4*i+3] << 24);
    }
    state[12] = counter;
    state[13] = ((uint32_t)nonce[0] << 0) |
                ((uint32_t)nonce[1] << 8) |
                ((uint32_t)nonce[2] << 16) |
                ((uint32_t)nonce[3] << 24);
    state[14] = ((uint32_t)nonce[4] << 0) |
                ((uint32_t)nonce[5] << 8) |
                ((uint32_t)nonce[6] << 16) |
                ((uint32_t)nonce[7] << 24);
    state[15] = ((uint32_t)nonce[8] << 0) |
                ((uint32_t)nonce[9] << 8) |
                ((uint32_t)nonce[10] << 16) |
                ((uint32_t)nonce[11] << 24);
    uint32_t working[16];
    for (int i = 0; i < 16; i++) working[i] = state[i];
    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(&working[0], &working[4], &working[8],  &working[12]);
        chacha20_quarter_round(&working[1], &working[5], &working[9],  &working[13]);
        chacha20_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarter_round(&working[3], &working[7], &working[11], &working[15]);
        chacha20_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarter_round(&working[2], &working[7], &working[8],  &working[13]);
        chacha20_quarter_round(&working[3], &working[4], &working[9],  &working[14]);
    }
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
        keystream[4*i]   = (working[i] >> 0) & 0xFF;
        keystream[4*i+1] = (working[i] >> 8) & 0xFF;
        keystream[4*i+2] = (working[i] >> 16) & 0xFF;
        keystream[4*i+3] = (working[i] >> 24) & 0xFF;
    }
}

static void chacha20_crypt(const unsigned char *key,
                           const unsigned char *nonce,
                           uint32_t *counter,
                           const unsigned char *in,
                           unsigned char *out,
                           size_t len) {
    unsigned char keystream[CHACHA20_BLOCK_SIZE];
    size_t processed = 0;
    while (processed < len) {
        chacha20_block(key, nonce, *counter, keystream);
        (*counter)++;
        size_t block = (len - processed) < CHACHA20_BLOCK_SIZE ? (len - processed) : CHACHA20_BLOCK_SIZE;
        for (size_t i = 0; i < block; i++) {
            out[processed + i] = in[processed + i] ^ keystream[i];
        }
        processed += block;
    }
}

/* ============================================================
 *  获取算法对应的加密密钥长度
 * ============================================================ */
static size_t cipher_key_len_for_algo(char algo) {
    switch (algo) {
        case UNICRYPTO_ALGO_SHA:
        case UNICRYPTO_ALGO_AES:
            return 16;
        case UNICRYPTO_ALGO_CHACHA:
            return 32;
        default:
            return 0;
    }
}

/* ============================================================
 *  加密核心函数（用于文件和内存，流式处理）
 * ============================================================ */

/* 加密一个数据块（压缩后的数据），根据算法处理，返回加密后的块和更新计数器 */
static int encrypt_block(char algo,
                         const unsigned char *cipher_key,
                         const unsigned char *nonce,
                         uint32_t *counter,
                         const unsigned char *plain,
                         size_t len,
                         unsigned char *cipher_out) {
    switch (algo) {
        case UNICRYPTO_ALGO_SHA: {
            // 生成密钥流并异或
            unsigned char keystream[CHUNK_SIZE];
            size_t written = 0;
            while (written < len) {
                unsigned char cbytes[4];
                cbytes[0] = (*counter >> 24) & 0xFF;
                cbytes[1] = (*counter >> 16) & 0xFF;
                cbytes[2] = (*counter >> 8) & 0xFF;
                cbytes[3] = *counter & 0xFF;
                unsigned char input[NONCE_LEN + 4];
                memcpy(input, nonce, NONCE_LEN);
                memcpy(input + NONCE_LEN, cbytes, 4);
                unsigned char digest[32];
                hmac_sha256(cipher_key, 16, input, NONCE_LEN + 4, digest);
                size_t to_copy = (len - written) < 32 ? (len - written) : 32;
                memcpy(keystream + written, digest, to_copy);
                written += to_copy;
                (*counter)++;
            }
            for (size_t i = 0; i < len; i++)
                cipher_out[i] = plain[i] ^ keystream[i];
            break;
        }
        case UNICRYPTO_ALGO_AES:
            aes_ctr_crypt(cipher_key, nonce, counter, plain, cipher_out, len);
            break;
        case UNICRYPTO_ALGO_CHACHA:
            chacha20_crypt(cipher_key, nonce, counter, plain, cipher_out, len);
            break;
        default:
            return UNICRYPTO_ERR_UNSUPPORTED;
    }
    return UNICRYPTO_OK;
}

/* ============================================================
 *  文件加密
 * ============================================================ */
unicrypto_error_t unicrypto_encrypt_file(const char *in_path, const char *out_path,
                                         const char *password, const char *mode,
                                         char algo) {
    int ret = UNICRYPTO_OK;
    FILE *fin = NULL, *fout = NULL, *tmp = NULL;
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    size_t cipher_key_len = cipher_key_len_for_algo(algo);
    if (cipher_key_len == 0) return UNICRYPTO_ERR_UNSUPPORTED;
    unsigned char *cipher_key = (unsigned char*)malloc(cipher_key_len);
    unsigned char mac_key[32];
    if (!cipher_key) return UNICRYPTO_ERR_MEM;
    unsigned char header_no_sig[HEADER_NO_SIG_LEN];
    unsigned char header[HEADER_FULL_LEN];
    unsigned char inbuf[CHUNK_SIZE];
    unsigned char compbuf[CHUNK_SIZE];
    unsigned char encbuf[CHUNK_SIZE];
    unsigned char sig[SIG_LEN];
    z_stream zs;
    hmac_sha256_ctx hmac_ctx;
    uint32_t counter = 0;
    int flush = Z_NO_FLUSH;
    long tmp_size;

    fin = fopen(in_path, "rb");
    if (!fin) { free(cipher_key); return UNICRYPTO_ERR_IO; }
    fout = fopen(out_path, "wb");
    if (!fout) { fclose(fin); free(cipher_key); return UNICRYPTO_ERR_IO; }

    tmp = tmpfile();
    if (!tmp) { ret = UNICRYPTO_ERR_IO; goto cleanup; }

    if (get_random_bytes(salt, SALT_LEN) != UNICRYPTO_OK ||
        get_random_bytes(nonce, NONCE_LEN) != UNICRYPTO_OK) {
        ret = UNICRYPTO_ERR_RANDOM; goto cleanup;
    }

    ret = derive_keys((const unsigned char*)password, strlen(password),
                      salt, SALT_LEN, cipher_key_len, cipher_key, mac_key);
    if (ret != UNICRYPTO_OK) goto cleanup;

    memcpy(header_no_sig, MAGIC, MAGIC_LEN);
    memcpy(header_no_sig + MAGIC_LEN, mode, 2);
    header_no_sig[MAGIC_LEN + 2] = (unsigned char)algo;
    memcpy(header_no_sig + MAGIC_LEN + 2 + 1, salt, SALT_LEN);
    memcpy(header_no_sig + MAGIC_LEN + 2 + 1 + SALT_LEN, nonce, NONCE_LEN);

    hmac_sha256_init(&hmac_ctx, mac_key, 32);
    hmac_sha256_update(&hmac_ctx, header_no_sig, HEADER_NO_SIG_LEN);

    memcpy(header, header_no_sig, HEADER_NO_SIG_LEN);
    memset(header + HEADER_NO_SIG_LEN, 0, SIG_LEN);
    if (fwrite(header, 1, HEADER_FULL_LEN, tmp) != HEADER_FULL_LEN) {
        ret = UNICRYPTO_ERR_IO; goto cleanup;
    }

    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) {
        ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup;
    }

    do {
        size_t bytes = fread(inbuf, 1, CHUNK_SIZE, fin);
        zs.avail_in = bytes;
        zs.next_in = inbuf;
        flush = feof(fin) ? Z_FINISH : Z_NO_FLUSH;

        do {
            zs.avail_out = CHUNK_SIZE;
            zs.next_out = compbuf;
            if (deflate(&zs, flush) == Z_STREAM_ERROR) {
                ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup;
            }
            size_t have = CHUNK_SIZE - zs.avail_out;
            if (have > 0) {
                // 加密压缩数据块
                ret = encrypt_block(algo, cipher_key, nonce, &counter,
                                    compbuf, have, encbuf);
                if (ret != UNICRYPTO_OK) goto cleanup;
                hmac_sha256_update(&hmac_ctx, encbuf, have);
                if (fwrite(encbuf, 1, have, tmp) != have) {
                    ret = UNICRYPTO_ERR_IO; goto cleanup;
                }
                // SHA 模式的计数器更新在 encrypt_block 内部已处理，
                // AES和ChaCha也处理了，但counter在函数内部已递增。
                // 不过对于SHA，我们已递增了counter，但次数可能不对应，因为在encrypt_block中循环递增，
                // 但我们在外部可能还需要调整？实际上encrypt_block已经更新了counter，但要注意传递指针。
                // 这里传递了&counter，所以在函数内部更新了。
                // 我们不需要额外操作。
            }
        } while (zs.avail_out == 0 && ret == UNICRYPTO_OK);
    } while (flush != Z_FINISH && ret == UNICRYPTO_OK);

    deflateEnd(&zs);

    hmac_sha256_final(&hmac_ctx, sig);

    fseek(tmp, HEADER_NO_SIG_LEN, SEEK_SET);
    if (fwrite(sig, 1, SIG_LEN, tmp) != SIG_LEN) {
        ret = UNICRYPTO_ERR_IO; goto cleanup;
    }

    fflush(tmp);
    fseek(tmp, 0, SEEK_END);
    tmp_size = ftell(tmp);
    fseek(tmp, 0, SEEK_SET);

    unsigned char readbuf[CHUNK_SIZE];
    while (tmp_size > 0) {
        size_t to_read = (tmp_size < (long)CHUNK_SIZE) ? (size_t)tmp_size : CHUNK_SIZE;
        if (fread(readbuf, 1, to_read, tmp) != to_read) {
            ret = UNICRYPTO_ERR_IO; goto cleanup;
        }
        if (strcmp(mode, "zc") == 0) {
            if (encode_zc_stream(fout, readbuf, to_read) != UNICRYPTO_OK) {
                ret = UNICRYPTO_ERR_IO; goto cleanup;
            }
        } else if (strcmp(mode, "zh") == 0) {
            if (encode_zh_stream(fout, readbuf, to_read) != UNICRYPTO_OK) {
                ret = UNICRYPTO_ERR_IO; goto cleanup;
            }
        } else {
            ret = UNICRYPTO_ERR_UNSUPPORTED; goto cleanup;
        }
        tmp_size -= to_read;
    }

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (tmp) fclose(tmp);
    free(cipher_key);
    return ret;
}

/* ============================================================
 *  文件解密
 * ============================================================ */
unicrypto_error_t unicrypto_decrypt_file(const char *in_path, const char *out_path,
                                         const char *password, int ignore_magic) {
    int ret = UNICRYPTO_OK;
    FILE *fin = NULL, *fout = NULL;
    unsigned char *text = NULL;
    size_t text_len = 0;
    unsigned char *binary = NULL;
    size_t binary_len = 0;
    unsigned char *header_no_sig = NULL;
    unsigned char *signature = NULL;
    unsigned char *ciphertext = NULL;
    size_t cipher_len = 0;
    char mode_flag[3] = {0};
    char algo = UNICRYPTO_ALGO_SHA; /* 默认 */
    unsigned char *salt = NULL, *nonce = NULL;
    size_t cipher_key_len = 0;
    unsigned char *cipher_key = NULL;
    unsigned char mac_key[32];
    unsigned char calc_sig[SIG_LEN];
    unsigned char *hmac_input = NULL;
    z_stream zs;
    unsigned char outbuf[CHUNK_SIZE];
    unsigned char decbuf[CHUNK_SIZE];
    uint32_t counter = 0;
    size_t processed = 0;

    fin = fopen(in_path, "rb");
    if (!fin) return UNICRYPTO_ERR_IO;
    fseek(fin, 0, SEEK_END);
    text_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    text = (unsigned char*)malloc(text_len + 1);
    if (!text) { ret = UNICRYPTO_ERR_MEM; goto cleanup; }
    if (fread(text, 1, text_len, fin) != text_len) { ret = UNICRYPTO_ERR_IO; goto cleanup; }
    text[text_len] = '\0';
    fclose(fin); fin = NULL;

    // 判断编码模式
    if (text_len == 0) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    uint32_t first_cp;
    int n = utf8_decode(text, text_len, &first_cp);
    if (n <= 0) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    int is_zc = (first_cp >= ZC_START && first_cp < ZC_START + ZC_BASE);
    int is_zh = (first_cp >= ZH_START && first_cp < ZH_START + ZH_BASE);
    if (!is_zc && !is_zh) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }

    if (is_zc) ret = decode_zc(text, text_len, &binary, &binary_len);
    else ret = decode_zh(text, text_len, &binary, &binary_len);
    free(text); text = NULL;
    if (ret != UNICRYPTO_OK) goto cleanup;

    // 解析头部：先检测是否为新格式（含算法标识）
    int is_new_format = 0;
    if (binary_len >= (MAGIC_LEN + 2 + 1)) {
        unsigned char maybe_algo = binary[MAGIC_LEN + 2];
        if (maybe_algo == UNICRYPTO_ALGO_SHA ||
            maybe_algo == UNICRYPTO_ALGO_AES ||
            maybe_algo == UNICRYPTO_ALGO_CHACHA) {
            is_new_format = 1;
        }
    }

    if (is_new_format) {
        if (binary_len < HEADER_FULL_LEN) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
        header_no_sig = binary;
        signature = binary + HEADER_NO_SIG_LEN;
        ciphertext = binary + HEADER_FULL_LEN;
        cipher_len = binary_len - HEADER_FULL_LEN;
        if (!ignore_magic && memcmp(header_no_sig, MAGIC, MAGIC_LEN) != 0) {
            ret = UNICRYPTO_ERR_FORMAT; goto cleanup;
        }
        memcpy(mode_flag, header_no_sig + MAGIC_LEN, 2);
        algo = header_no_sig[MAGIC_LEN + 2];
        salt = header_no_sig + MAGIC_LEN + 2 + 1;
        nonce = salt + SALT_LEN;
    } else {
        // 旧格式：无算法标识
        size_t old_header_len = MAGIC_LEN + 2 + SALT_LEN + NONCE_LEN + SIG_LEN;
        if (binary_len < old_header_len) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
        header_no_sig = binary;
        signature = binary + (MAGIC_LEN + 2 + SALT_LEN + NONCE_LEN);
        ciphertext = binary + old_header_len;
        cipher_len = binary_len - old_header_len;
        if (!ignore_magic && memcmp(header_no_sig, MAGIC, MAGIC_LEN) != 0) {
            ret = UNICRYPTO_ERR_FORMAT; goto cleanup;
        }
        memcpy(mode_flag, header_no_sig + MAGIC_LEN, 2);
        algo = UNICRYPTO_ALGO_SHA;  // 默认
        salt = header_no_sig + MAGIC_LEN + 2;
        nonce = salt + SALT_LEN;
        // 构造一个临时header_no_sig用于HMAC计算（实际旧头部不含算法标识，但HMAC只计算头部的有效部分）
        // 但为了统一，我们重新构建一个不含签名的头部（包括算法标识）用于校验？
        // 为了兼容，我们构建一个与新格式相同的头部（但原旧格式没有算法标识，我们补上算法标识's'）
        // 但HMAC是对头部（不含签名）进行计算的，所以我们需要用同样的头部计算HMAC。
        // 在旧格式中，头部不含算法标识，HMAC计算时也不包含该字节。所以我们需按旧格式方式计算。
        // 但为了代码统一，我们构造一个新的header_no_sig_old，包含MAGIC+模式+SALT+NONCE（无算法），然后HMAC。
        // 我们在此处构建一个临时缓冲区，以便后续HMAC计算。
        // 因旧格式头部无算法，我们重新组织一个字段用于HMAC，但为了保证一致性，我们将旧格式的头部（不含算法）传给HMAC。
        // 但我们的HMAC函数期望头部含算法，所以我们需要特殊处理。
        // 简单：我们保留旧格式的header_no_sig指针，但计算HMAC时需要跳过算法标识。
        // 我们可以在计算HMAC时，只对前MAGIC_LEN+2+SALT_LEN+NONCE_LEN字节计算，而忽略算法标识。
        // 对于新格式，计算HEADER_NO_SIG_LEN长度。
        // 为简化，我们在这里创建一个局部标志，在HMAC计算时分别处理。
    }

    if (strcmp(mode_flag, "zc") != 0 && strcmp(mode_flag, "zh") != 0) {
        ret = UNICRYPTO_ERR_UNSUPPORTED; goto cleanup;
    }

    cipher_key_len = cipher_key_len_for_algo(algo);
    if (cipher_key_len == 0) { ret = UNICRYPTO_ERR_UNSUPPORTED; goto cleanup; }
    cipher_key = (unsigned char*)malloc(cipher_key_len);
    if (!cipher_key) { ret = UNICRYPTO_ERR_MEM; goto cleanup; }

    if (!password) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    ret = derive_keys((const unsigned char*)password, strlen(password),
                      salt, SALT_LEN, cipher_key_len, cipher_key, mac_key);
    if (ret != UNICRYPTO_OK) goto cleanup;

    // 计算HMAC
    // 对于新格式，头部长度=HEADER_NO_SIG_LEN；旧格式，头部长度= MAGIC_LEN+2+SALT_LEN+NONCE_LEN
    size_t hdr_len_for_hmac = is_new_format ? HEADER_NO_SIG_LEN : (MAGIC_LEN + 2 + SALT_LEN + NONCE_LEN);
    hmac_input = (unsigned char*)malloc(hdr_len_for_hmac + cipher_len);
    if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; goto cleanup; }
    if (is_new_format) {
        memcpy(hmac_input, header_no_sig, hdr_len_for_hmac);
    } else {
        // 旧格式：只复制 MAGIC + 模式 + SALT + NONCE（不含算法）
        memcpy(hmac_input, header_no_sig, MAGIC_LEN);
        memcpy(hmac_input + MAGIC_LEN, header_no_sig + MAGIC_LEN, 2);
        memcpy(hmac_input + MAGIC_LEN + 2, salt, SALT_LEN + NONCE_LEN);
    }
    memcpy(hmac_input + hdr_len_for_hmac, ciphertext, cipher_len);
    hmac_sha256(mac_key, 32, hmac_input, hdr_len_for_hmac + cipher_len, calc_sig);
    free(hmac_input); hmac_input = NULL;
    if (!ignore_magic && memcmp(signature, calc_sig, SIG_LEN) != 0) {
        ret = UNICRYPTO_ERR_HMAC; goto cleanup;
    }

    fout = fopen(out_path, "wb");
    if (!fout) { ret = UNICRYPTO_ERR_IO; goto cleanup; }

    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) { ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup; }

    counter = 0;
    processed = 0;
    while (processed < cipher_len) {
        size_t block = CHUNK_SIZE;
        if (processed + block > cipher_len) block = cipher_len - processed;

        // 解密块
        ret = encrypt_block(algo, cipher_key, nonce, &counter,
                            ciphertext + processed, block, decbuf);
        if (ret != UNICRYPTO_OK) goto cleanup;

        zs.avail_in = block;
        zs.next_in = decbuf;
        do {
            zs.avail_out = CHUNK_SIZE;
            zs.next_out = outbuf;
            if (inflate(&zs, Z_SYNC_FLUSH) == Z_STREAM_ERROR) {
                ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup;
            }
            size_t have = CHUNK_SIZE - zs.avail_out;
            if (have > 0) {
                if (fwrite(outbuf, 1, have, fout) != have) {
                    ret = UNICRYPTO_ERR_IO; goto cleanup;
                }
            }
        } while (zs.avail_out == 0);

        processed += block;
    }
    inflateEnd(&zs);

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    free(text);
    free(binary);
    free(cipher_key);
    return ret;
}

/* ============================================================
 *  内存压缩/解压辅助
 * ============================================================ */
static int compress_mem(const unsigned char *src, size_t src_len,
                        unsigned char **dst, size_t *dst_len) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK)
        return UNICRYPTO_ERR_DECOMPRESS;
    size_t cap = src_len + 1024;
    unsigned char *buf = (unsigned char*)malloc(cap);
    if (!buf) { deflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
    size_t written = 0;
    zs.next_in = (Bytef*)src;
    zs.avail_in = src_len;
    int flush = Z_FINISH;
    int ret;
    do {
        if (written + CHUNK_SIZE > cap) {
            cap *= 2;
            unsigned char *tmp = (unsigned char*)realloc(buf, cap);
            if (!tmp) { free(buf); deflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
            buf = tmp;
        }
        zs.avail_out = CHUNK_SIZE;
        zs.next_out = (Bytef*)buf + written;
        ret = deflate(&zs, flush);
        if (ret == Z_STREAM_ERROR) { free(buf); deflateEnd(&zs); return UNICRYPTO_ERR_DECOMPRESS; }
        written += CHUNK_SIZE - zs.avail_out;
    } while (zs.avail_out == 0);
    deflateEnd(&zs);
    *dst = buf;
    *dst_len = written;
    return UNICRYPTO_OK;
}

static int decompress_mem(const unsigned char *src, size_t src_len,
                          unsigned char **dst, size_t *dst_len) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK)
        return UNICRYPTO_ERR_DECOMPRESS;
    size_t cap = CHUNK_SIZE;
    unsigned char *buf = (unsigned char*)malloc(cap);
    if (!buf) { inflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
    size_t written = 0;
    zs.next_in = (Bytef*)src;
    zs.avail_in = src_len;
    int ret;
    do {
        if (written + CHUNK_SIZE > cap) {
            cap *= 2;
            unsigned char *tmp = (unsigned char*)realloc(buf, cap);
            if (!tmp) { free(buf); inflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
            buf = tmp;
        }
        zs.avail_out = CHUNK_SIZE;
        zs.next_out = (Bytef*)buf + written;
        ret = inflate(&zs, Z_SYNC_FLUSH);
        if (ret == Z_STREAM_ERROR) { free(buf); inflateEnd(&zs); return UNICRYPTO_ERR_DECOMPRESS; }
        written += CHUNK_SIZE - zs.avail_out;
    } while (zs.avail_out == 0);
    inflateEnd(&zs);
    *dst = buf;
    *dst_len = written;
    return UNICRYPTO_OK;
}

/* ============================================================
 *  内存缓冲区接口
 * ============================================================ */
unicrypto_error_t unicrypto_encrypt_buf(const unsigned char *input, size_t input_len,
                                        unsigned char **output, size_t *output_len,
                                        const char *password, const char *mode,
                                        char algo) {
    int ret = UNICRYPTO_OK;
    unsigned char *compressed = NULL;
    size_t comp_len = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *encoded = NULL;
    size_t enc_len = 0;
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    size_t cipher_key_len = cipher_key_len_for_algo(algo);
    if (cipher_key_len == 0) return UNICRYPTO_ERR_UNSUPPORTED;
    unsigned char *cipher_key = (unsigned char*)malloc(cipher_key_len);
    if (!cipher_key) return UNICRYPTO_ERR_MEM;
    unsigned char mac_key[32];
    unsigned char header_no_sig[HEADER_NO_SIG_LEN];
    unsigned char signature[SIG_LEN];
    unsigned char *hmac_input = NULL;
    unsigned char *total_data = NULL;
    uint32_t counter = 0;
    size_t processed = 0;

    do {
        ret = compress_mem(input, input_len, &compressed, &comp_len);
        if (ret != UNICRYPTO_OK) break;

        if (get_random_bytes(salt, SALT_LEN) != UNICRYPTO_OK ||
            get_random_bytes(nonce, NONCE_LEN) != UNICRYPTO_OK) {
            ret = UNICRYPTO_ERR_RANDOM; break;
        }

        ret = derive_keys((const unsigned char*)password, strlen(password),
                          salt, SALT_LEN, cipher_key_len, cipher_key, mac_key);
        if (ret != UNICRYPTO_OK) break;

        memcpy(header_no_sig, MAGIC, MAGIC_LEN);
        memcpy(header_no_sig + MAGIC_LEN, mode, 2);
        header_no_sig[MAGIC_LEN + 2] = (unsigned char)algo;
        memcpy(header_no_sig + MAGIC_LEN + 2 + 1, salt, SALT_LEN);
        memcpy(header_no_sig + MAGIC_LEN + 2 + 1 + SALT_LEN, nonce, NONCE_LEN);

        ciphertext = (unsigned char*)malloc(comp_len);
        if (!ciphertext) { ret = UNICRYPTO_ERR_MEM; break; }
        counter = 0; processed = 0;
        while (processed < comp_len) {
            size_t block = CHUNK_SIZE;
            if (processed + block > comp_len) block = comp_len - processed;
            ret = encrypt_block(algo, cipher_key, nonce, &counter,
                                compressed + processed, block,
                                ciphertext + processed);
            if (ret != UNICRYPTO_OK) break;
            processed += block;
        }
        if (ret != UNICRYPTO_OK) break;

        hmac_input = (unsigned char*)malloc(HEADER_NO_SIG_LEN + comp_len);
        if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(hmac_input, header_no_sig, HEADER_NO_SIG_LEN);
        memcpy(hmac_input + HEADER_NO_SIG_LEN, ciphertext, comp_len);
        hmac_sha256(mac_key, 32, hmac_input, HEADER_NO_SIG_LEN + comp_len, signature);
        free(hmac_input); hmac_input = NULL;

        size_t total = HEADER_NO_SIG_LEN + SIG_LEN + comp_len;
        total_data = (unsigned char*)malloc(total);
        if (!total_data) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(total_data, header_no_sig, HEADER_NO_SIG_LEN);
        memcpy(total_data + HEADER_NO_SIG_LEN, signature, SIG_LEN);
        memcpy(total_data + HEADER_NO_SIG_LEN + SIG_LEN, ciphertext, comp_len);

        if (strcmp(mode, "zc") == 0)
            ret = encode_zc(total_data, total, &encoded, &enc_len);
        else if (strcmp(mode, "zh") == 0)
            ret = encode_zh(total_data, total, &encoded, &enc_len);
        else
            ret = UNICRYPTO_ERR_UNSUPPORTED;
        free(total_data); total_data = NULL;
        if (ret != UNICRYPTO_OK) break;

        *output = encoded;
        *output_len = enc_len;
        encoded = NULL;
    } while (0);

    free(compressed);
    free(ciphertext);
    free(encoded);
    free(cipher_key);
    return ret;
}

unicrypto_error_t unicrypto_decrypt_buf(const unsigned char *input, size_t input_len,
                                        unsigned char **output, size_t *output_len,
                                        const char *password, int ignore_magic) {
    int ret = UNICRYPTO_OK;
    unsigned char *text = NULL;
    unsigned char *binary = NULL;
    size_t binary_len = 0;
    unsigned char *header_no_sig = NULL;
    unsigned char *signature = NULL;
    unsigned char *ciphertext = NULL;
    size_t cipher_len = 0;
    char mode_flag[3] = {0};
    char algo = UNICRYPTO_ALGO_SHA;
    unsigned char *salt = NULL, *nonce = NULL;
    size_t cipher_key_len = 0;
    unsigned char *cipher_key = NULL;
    unsigned char mac_key[32];
    unsigned char *hmac_input = NULL;
    unsigned char calc_sig[SIG_LEN];
    uint32_t counter = 0;
    size_t processed = 0;
    unsigned char *decrypted = NULL;
    unsigned char *decomp_buf = NULL;
    size_t decomp_len = 0;

    do {
        text = (unsigned char*)malloc(input_len + 1);
        if (!text) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(text, input, input_len);
        text[input_len] = '\0';

        if (input_len == 0) { ret = UNICRYPTO_ERR_FORMAT; break; }
        uint32_t first_cp;
        int n = utf8_decode(text, input_len, &first_cp);
        if (n <= 0) { ret = UNICRYPTO_ERR_FORMAT; break; }
        int is_zc = (first_cp >= ZC_START && first_cp < ZC_START + ZC_BASE);
        int is_zh = (first_cp >= ZH_START && first_cp < ZH_START + ZH_BASE);
        if (!is_zc && !is_zh) { ret = UNICRYPTO_ERR_FORMAT; break; }

        if (is_zc) ret = decode_zc(text, input_len, &binary, &binary_len);
        else ret = decode_zh(text, input_len, &binary, &binary_len);
        free(text); text = NULL;
        if (ret != UNICRYPTO_OK) break;

        // 检测新格式
        int is_new_format = 0;
        if (binary_len >= (MAGIC_LEN + 2 + 1)) {
            unsigned char maybe_algo = binary[MAGIC_LEN + 2];
            if (maybe_algo == UNICRYPTO_ALGO_SHA ||
                maybe_algo == UNICRYPTO_ALGO_AES ||
                maybe_algo == UNICRYPTO_ALGO_CHACHA) {
                is_new_format = 1;
            }
        }

        if (is_new_format) {
            if (binary_len < HEADER_FULL_LEN) { ret = UNICRYPTO_ERR_FORMAT; break; }
            header_no_sig = binary;
            signature = binary + HEADER_NO_SIG_LEN;
            ciphertext = binary + HEADER_FULL_LEN;
            cipher_len = binary_len - HEADER_FULL_LEN;
            if (!ignore_magic && memcmp(header_no_sig, MAGIC, MAGIC_LEN) != 0) {
                ret = UNICRYPTO_ERR_FORMAT; break;
            }
            memcpy(mode_flag, header_no_sig + MAGIC_LEN, 2);
            algo = header_no_sig[MAGIC_LEN + 2];
            salt = header_no_sig + MAGIC_LEN + 2 + 1;
            nonce = salt + SALT_LEN;
        } else {
            size_t old_header_len = MAGIC_LEN + 2 + SALT_LEN + NONCE_LEN + SIG_LEN;
            if (binary_len < old_header_len) { ret = UNICRYPTO_ERR_FORMAT; break; }
            header_no_sig = binary;
            signature = binary + (MAGIC_LEN + 2 + SALT_LEN + NONCE_LEN);
            ciphertext = binary + old_header_len;
            cipher_len = binary_len - old_header_len;
            if (!ignore_magic && memcmp(header_no_sig, MAGIC, MAGIC_LEN) != 0) {
                ret = UNICRYPTO_ERR_FORMAT; break;
            }
            memcpy(mode_flag, header_no_sig + MAGIC_LEN, 2);
            algo = UNICRYPTO_ALGO_SHA;
            salt = header_no_sig + MAGIC_LEN + 2;
            nonce = salt + SALT_LEN;
        }

        if (strcmp(mode_flag, "zc") != 0 && strcmp(mode_flag, "zh") != 0) {
            ret = UNICRYPTO_ERR_UNSUPPORTED; break;
        }

        cipher_key_len = cipher_key_len_for_algo(algo);
        if (cipher_key_len == 0) { ret = UNICRYPTO_ERR_UNSUPPORTED; break; }
        cipher_key = (unsigned char*)malloc(cipher_key_len);
        if (!cipher_key) { ret = UNICRYPTO_ERR_MEM; break; }

        if (!password) { ret = UNICRYPTO_ERR_FORMAT; break; }
        ret = derive_keys((const unsigned char*)password, strlen(password),
                          salt, SALT_LEN, cipher_key_len, cipher_key, mac_key);
        if (ret != UNICRYPTO_OK) break;

        size_t hdr_len_for_hmac = is_new_format ? HEADER_NO_SIG_LEN : (MAGIC_LEN + 2 + SALT_LEN + NONCE_LEN);
        hmac_input = (unsigned char*)malloc(hdr_len_for_hmac + cipher_len);
        if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; break; }
        if (is_new_format) {
            memcpy(hmac_input, header_no_sig, hdr_len_for_hmac);
        } else {
            memcpy(hmac_input, header_no_sig, MAGIC_LEN);
            memcpy(hmac_input + MAGIC_LEN, header_no_sig + MAGIC_LEN, 2);
            memcpy(hmac_input + MAGIC_LEN + 2, salt, SALT_LEN + NONCE_LEN);
        }
        memcpy(hmac_input + hdr_len_for_hmac, ciphertext, cipher_len);
        hmac_sha256(mac_key, 32, hmac_input, hdr_len_for_hmac + cipher_len, calc_sig);
        free(hmac_input); hmac_input = NULL;
        if (!ignore_magic && memcmp(signature, calc_sig, SIG_LEN) != 0) {
            ret = UNICRYPTO_ERR_HMAC; break;
        }

        decrypted = (unsigned char*)malloc(cipher_len);
        if (!decrypted) { ret = UNICRYPTO_ERR_MEM; break; }
        counter = 0; processed = 0;
        while (processed < cipher_len) {
            size_t block = CHUNK_SIZE;
            if (processed + block > cipher_len) block = cipher_len - processed;
            ret = encrypt_block(algo, cipher_key, nonce, &counter,
                                ciphertext + processed, block,
                                decrypted + processed);
            if (ret != UNICRYPTO_OK) break;
            processed += block;
        }
        if (ret != UNICRYPTO_OK) break;

        ret = decompress_mem(decrypted, cipher_len, &decomp_buf, &decomp_len);
        if (ret != UNICRYPTO_OK) break;

        *output = decomp_buf;
        *output_len = decomp_len;
        decomp_buf = NULL;
    } while (0);

    free(text);
    free(binary);
    free(decrypted);
    free(decomp_buf);
    free(cipher_key);
    return ret;
}

void unicrypto_free(void *ptr) {
    free(ptr);
}