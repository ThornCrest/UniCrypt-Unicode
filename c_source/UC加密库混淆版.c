#include "unicrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <zlib.h>
#include <fcntl.h>
#include <unistd.h>

/* ---------- 常量（全部用 C+数字 命名） ---------- */
#define C1  "EN10"
#define C2  4
#define C3  16
#define C4  12
#define C5  32
#define C6  48
#define C7  600000
#define C8  65536

#define C9  "zc"
#define C10 "zh"

#define C11 112
#define C12 0x0300
#define C13 256
#define C14 0x4E00

/* 错误描述（API 保留） */
const char* unicrypto_strerror(unicrypto_error_t err) {
    switch(err) {
        case UNICRYPTO_OK: return "成功";
        case UNICRYPTO_ERR_IO: return "I/O错误";
        case UNICRYPTO_ERR_MEM: return "内存不足";
        case UNICRYPTO_ERR_FORMAT: return "文件格式错误";
        case UNICRYPTO_ERR_HMAC: return "HMAC验证失败";
        case UNICRYPTO_ERR_DECOMPRESS: return "解压失败";
        case UNICRYPTO_ERR_RANDOM: return "随机数生成失败";
        case UNICRYPTO_ERR_UNSUPPORTED: return "不支持的编码模式";
        default: return "未知错误";
    }
}

/* ============================================================
 *  SHA-256（全部 static，用 f1~f4 和 s1）
 * ============================================================ */
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[SHA256_BLOCK_SIZE];
} s1;

static const uint32_t K1[64] = {
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

static void f1(s1 *ctx) {
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
        t1 = h + S1 + ch + K1[i] + W[i];
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

static void f2(s1 *ctx) {
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

static void f3(s1 *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = data[i];
        ctx->count++;
        if (ctx->count % SHA256_BLOCK_SIZE == 0) {
            f1(ctx);
        }
    }
}

static void f4(s1 *ctx, unsigned char *digest) {
    uint64_t bit_len = ctx->count * 8;
    unsigned char pad[64];
    int pad_len = (ctx->count % SHA256_BLOCK_SIZE < 56) ? (56 - ctx->count % SHA256_BLOCK_SIZE) : (120 - ctx->count % SHA256_BLOCK_SIZE);
    pad[0] = 0x80;
    for (int i = 1; i < pad_len; i++) pad[i] = 0;
    f3(ctx, pad, pad_len);
    unsigned char len_buf[8];
    for (int i = 0; i < 8; i++) len_buf[7-i] = (bit_len >> (i*8)) & 0xFF;
    f3(ctx, len_buf, 8);
    for (int i = 0; i < 8; i++) {
        digest[i*4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4+3] = ctx->state[i] & 0xFF;
    }
}

/* ============================================================
 *  HMAC-SHA256（一次性 + 增量，f5~f8，结构体 s2）
 * ============================================================ */
static void f5(const unsigned char *key, size_t key_len,
               const unsigned char *msg, size_t msg_len,
               unsigned char *out) {
    unsigned char k_ipad[SHA256_BLOCK_SIZE];
    unsigned char k_opad[SHA256_BLOCK_SIZE];
    unsigned char tk[SHA256_DIGEST_SIZE];
    size_t i;
    if (key_len > SHA256_BLOCK_SIZE) {
        s1 ctx;
        f2(&ctx);
        f3(&ctx, key, key_len);
        f4(&ctx, tk);
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
    s1 ctx;
    f2(&ctx);
    f3(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    f3(&ctx, msg, msg_len);
    unsigned char inner_hash[SHA256_DIGEST_SIZE];
    f4(&ctx, inner_hash);
    f2(&ctx);
    f3(&ctx, k_opad, SHA256_BLOCK_SIZE);
    f3(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    f4(&ctx, out);
}

typedef struct {
    s1 inner, outer;
} s2;

static void f6(s2 *ctx, const unsigned char *key, size_t key_len) {
    unsigned char k[SHA256_BLOCK_SIZE];
    memset(k, 0, SHA256_BLOCK_SIZE);
    if (key_len > SHA256_BLOCK_SIZE) {
        s1 tmp;
        f2(&tmp);
        f3(&tmp, key, key_len);
        f4(&tmp, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k[i] ^= 0x36;
    }
    f2(&ctx->inner);
    f3(&ctx->inner, k, SHA256_BLOCK_SIZE);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k[i] ^= (0x36 ^ 0x5c);
    }
    f2(&ctx->outer);
    f3(&ctx->outer, k, SHA256_BLOCK_SIZE);
}

static void f7(s2 *ctx, const unsigned char *data, size_t len) {
    f3(&ctx->inner, data, len);
}

static void f8(s2 *ctx, unsigned char *out) {
    unsigned char inner_hash[SHA256_DIGEST_SIZE];
    f4(&ctx->inner, inner_hash);
    f3(&ctx->outer, inner_hash, SHA256_DIGEST_SIZE);
    f4(&ctx->outer, out);
}

/* ============================================================
 *  PBKDF2-HMAC-SHA256（f9）
 * ============================================================ */
static int f9(const unsigned char *pass, size_t pass_len,
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
        f5(pass, pass_len, msg, salt_len + 4, U);
        memcpy(T, U, 32);
        for (uint32_t i = 1; i < iterations; i++) {
            f5(pass, pass_len, U, 32, U);
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
 *  随机数（f10）
 * ============================================================ */
static int f10(unsigned char *buf, size_t len) {
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
 *  UTF-8 编解码（f11, f12）
 * ============================================================ */
static int f11(uint32_t cp, unsigned char *out) {
    if (cp <= 0x7F) { out[0] = cp; return 1; }
    else if (cp <= 0x7FF) { out[0] = 0xC0 | ((cp >> 6) & 0x1F); out[1] = 0x80 | (cp & 0x3F); return 2; }
    else if (cp <= 0xFFFF) { out[0] = 0xE0 | ((cp >> 12) & 0x0F); out[1] = 0x80 | ((cp >> 6) & 0x3F); out[2] = 0x80 | (cp & 0x3F); return 3; }
    else if (cp <= 0x10FFFF) { out[0] = 0xF0 | ((cp >> 18) & 0x07); out[1] = 0x80 | ((cp >> 12) & 0x3F); out[2] = 0x80 | ((cp >> 6) & 0x3F); out[3] = 0x80 | (cp & 0x3F); return 4; }
    return -1;
}

static int f12(const unsigned char *buf, size_t len, uint32_t *cp) {
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
 *  ZC / ZH 编码器（批量，f13~f16）
 * ============================================================ */
static int f13(const unsigned char *data, size_t len,
               unsigned char **out, size_t *out_len) {
    size_t max_out = len * 2 * 3 + 1;
    unsigned char *buf = (unsigned char*)malloc(max_out);
    if (!buf) return UNICRYPTO_ERR_MEM;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        int high = data[i] / C11;
        int low  = data[i] % C11;
        int n1 = f11(C12 + high, buf + pos);
        int n2 = f11(C12 + low,  buf + pos + n1);
        if (n1 < 0 || n2 < 0) { free(buf); return UNICRYPTO_ERR_FORMAT; }
        pos += n1 + n2;
    }
    *out = buf;
    *out_len = pos;
    return UNICRYPTO_OK;
}

static int f14(const unsigned char *utf8, size_t utf8_len,
               unsigned char **out, size_t *out_len) {
    size_t chars = 0;
    size_t idx = 0;
    while (idx < utf8_len) {
        uint32_t cp;
        int n = f12(utf8 + idx, utf8_len - idx, &cp);
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
        int n1 = f12(utf8 + idx, utf8_len - idx, &cp1); idx += n1;
        int n2 = f12(utf8 + idx, utf8_len - idx, &cp2); idx += n2;
        if (cp1 < C12 || cp1 >= C12 + C11 ||
            cp2 < C12 || cp2 >= C12 + C11) {
            free(buf); return UNICRYPTO_ERR_FORMAT;
        }
        int high = cp1 - C12;
        int low  = cp2 - C12;
        buf[out_pos++] = (unsigned char)(high * C11 + low);
    }
    *out = buf;
    *out_len = out_pos;
    return UNICRYPTO_OK;
}

static int f15(const unsigned char *data, size_t len,
               unsigned char **out, size_t *out_len) {
    size_t max_out = len * 3 + 1;
    unsigned char *buf = (unsigned char*)malloc(max_out);
    if (!buf) return UNICRYPTO_ERR_MEM;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        int n = f11(C14 + data[i], buf + pos);
        if (n < 0) { free(buf); return UNICRYPTO_ERR_FORMAT; }
        pos += n;
    }
    *out = buf;
    *out_len = pos;
    return UNICRYPTO_OK;
}

static int f16(const unsigned char *utf8, size_t utf8_len,
               unsigned char **out, size_t *out_len) {
    unsigned char *buf = (unsigned char*)malloc(utf8_len);
    if (!buf) return UNICRYPTO_ERR_MEM;
    size_t idx = 0, out_pos = 0;
    while (idx < utf8_len) {
        uint32_t cp;
        int n = f12(utf8 + idx, utf8_len - idx, &cp);
        if (n <= 0) { free(buf); return UNICRYPTO_ERR_FORMAT; }
        idx += n;
        if (cp < C14 || cp >= C14 + C13) {
            free(buf); return UNICRYPTO_ERR_FORMAT;
        }
        buf[out_pos++] = (unsigned char)(cp - C14);
    }
    *out = buf;
    *out_len = out_pos;
    return UNICRYPTO_OK;
}

/* ============================================================
 *  流式编码器（f17, f18）
 * ============================================================ */
static int f17(FILE *out, const unsigned char *data, size_t len) {
    unsigned char buf[6];
    for (size_t i = 0; i < len; i++) {
        int high = data[i] / C11;
        int low  = data[i] % C11;
        int n1 = f11(C12 + high, buf);
        int n2 = f11(C12 + low,  buf + n1);
        if (fwrite(buf, 1, n1 + n2, out) != (size_t)(n1 + n2))
            return UNICRYPTO_ERR_IO;
    }
    return UNICRYPTO_OK;
}

static int f18(FILE *out, const unsigned char *data, size_t len) {
    unsigned char buf[3];
    for (size_t i = 0; i < len; i++) {
        int n = f11(C14 + data[i], buf);
        if (fwrite(buf, 1, n, out) != (size_t)n)
            return UNICRYPTO_ERR_IO;
    }
    return UNICRYPTO_OK;
}

/* ============================================================
 *  密钥派生与密钥流（f19~f21）
 * ============================================================ */
static int f19(const unsigned char *pass, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned char *cipher_key, unsigned char *mac_key) {
    unsigned char key_material[C6];
    if (f9(pass, pass_len, salt, salt_len, C7, C6, key_material) != 0)
        return UNICRYPTO_ERR_MEM;
    memcpy(cipher_key, key_material, 16);
    memcpy(mac_key, key_material + 16, 32);
    return UNICRYPTO_OK;
}

static unsigned char* f20(const unsigned char *cipher_key,
                          const unsigned char *nonce,
                          uint32_t counter, size_t needed) {
    unsigned char *stream = (unsigned char*)malloc(needed);
    if (!stream) return NULL;
    size_t written = 0;
    while (written < needed) {
        unsigned char cbytes[4];
        cbytes[0] = (counter >> 24) & 0xFF;
        cbytes[1] = (counter >> 16) & 0xFF;
        cbytes[2] = (counter >> 8) & 0xFF;
        cbytes[3] = counter & 0xFF;
        unsigned char input[C4 + 4];
        memcpy(input, nonce, C4);
        memcpy(input + C4, cbytes, 4);
        unsigned char digest[32];
        f5(cipher_key, 16, input, C4 + 4, digest);
        size_t to_copy = (needed - written) < 32 ? (needed - written) : 32;
        memcpy(stream + written, digest, to_copy);
        written += to_copy;
        counter++;
    }
    return stream;
}

static void f21(const unsigned char *cipher_key,
                const unsigned char *nonce,
                uint32_t counter,
                size_t needed,
                unsigned char *out) {
    size_t written = 0;
    while (written < needed) {
        unsigned char cbytes[4];
        cbytes[0] = (counter >> 24) & 0xFF;
        cbytes[1] = (counter >> 16) & 0xFF;
        cbytes[2] = (counter >> 8) & 0xFF;
        cbytes[3] = counter & 0xFF;
        unsigned char input[C4 + 4];
        memcpy(input, nonce, C4);
        memcpy(input + C4, cbytes, 4);
        unsigned char digest[32];
        f5(cipher_key, 16, input, C4 + 4, digest);
        size_t to_copy = (needed - written) < 32 ? (needed - written) : 32;
        memcpy(out + written, digest, to_copy);
        written += to_copy;
        counter++;
    }
}

/* ============================================================
 *  内存压缩/解压辅助（f22, f23）
 * ============================================================ */
static int f22(const unsigned char *src, size_t src_len,
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
        if (written + C8 > cap) {
            cap *= 2;
            unsigned char *tmp = (unsigned char*)realloc(buf, cap);
            if (!tmp) { free(buf); deflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
            buf = tmp;
        }
        zs.avail_out = C8;
        zs.next_out = (Bytef*)buf + written;
        ret = deflate(&zs, flush);
        if (ret == Z_STREAM_ERROR) { free(buf); deflateEnd(&zs); return UNICRYPTO_ERR_DECOMPRESS; }
        written += C8 - zs.avail_out;
    } while (zs.avail_out == 0);
    deflateEnd(&zs);
    *dst = buf;
    *dst_len = written;
    return UNICRYPTO_OK;
}

/* 修复后的解压函数（正确处理所有输入并输出完整数据） */
static int f23(const unsigned char *src, size_t src_len,
               unsigned char **dst, size_t *dst_len) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK)
        return UNICRYPTO_ERR_DECOMPRESS;
    size_t cap = C8;
    unsigned char *buf = (unsigned char*)malloc(cap);
    if (!buf) { inflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
    size_t written = 0;
    zs.next_in = (Bytef*)src;
    zs.avail_in = src_len;
    int ret = Z_OK;
    int flush = Z_NO_FLUSH;
    while (ret != Z_STREAM_END) {
        if (zs.avail_in == 0 && ret == Z_OK) {
            flush = Z_FINISH;
        }
        if (written + C8 > cap) {
            cap *= 2;
            unsigned char *tmp = (unsigned char*)realloc(buf, cap);
            if (!tmp) { free(buf); inflateEnd(&zs); return UNICRYPTO_ERR_MEM; }
            buf = tmp;
        }
        zs.avail_out = C8;
        zs.next_out = (Bytef*)buf + written;
        ret = inflate(&zs, flush);
        if (ret == Z_STREAM_ERROR) { free(buf); inflateEnd(&zs); return UNICRYPTO_ERR_DECOMPRESS; }
        written += C8 - zs.avail_out;
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            free(buf);
            inflateEnd(&zs);
            return UNICRYPTO_ERR_DECOMPRESS;
        }
    }
    if (ret != Z_STREAM_END) {
        free(buf);
        inflateEnd(&zs);
        return UNICRYPTO_ERR_DECOMPRESS;
    }
    inflateEnd(&zs);
    *dst = buf;
    *dst_len = written;
    return UNICRYPTO_OK;
}

/* ============================================================
 *  文件加密（公开 API）
 * ============================================================ */
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_file(const char *in_path, const char *out_path,
                                                       const char *password, const char *mode) {
    int ret = UNICRYPTO_OK;
    FILE *fin = NULL, *fout = NULL, *tmp = NULL;
    unsigned char salt[C3], nonce[C4];
    unsigned char cipher_key[16], mac_key[32];
    unsigned char header_no_sig[4 + 2 + C3 + C4];
    unsigned char header[4 + 2 + C3 + C4 + C5];
    size_t header_no_sig_len = 4 + 2 + C3 + C4;
    size_t full_header_len = header_no_sig_len + C5;
    unsigned char inbuf[C8];
    unsigned char compbuf[C8];
    unsigned char encbuf[C8];
    unsigned char keystream_buf[C8];
    unsigned char sig[C5];
    z_stream zs;
    s2 hmac_ctx;
    uint32_t counter = 0;
    int flush = Z_NO_FLUSH;
    long tmp_size;

    fin = fopen(in_path, "rb");
    if (!fin) return UNICRYPTO_ERR_IO;
    fout = fopen(out_path, "wb");
    if (!fout) { fclose(fin); return UNICRYPTO_ERR_IO; }

    tmp = tmpfile();
    if (!tmp) { ret = UNICRYPTO_ERR_IO; goto cleanup; }

    if (f10(salt, C3) != UNICRYPTO_OK ||
        f10(nonce, C4) != UNICRYPTO_OK) {
        ret = UNICRYPTO_ERR_RANDOM; goto cleanup;
    }

    ret = f19((const unsigned char*)password, strlen(password),
              salt, C3, cipher_key, mac_key);
    if (ret != UNICRYPTO_OK) goto cleanup;

    memcpy(header_no_sig, C1, 4);
    memcpy(header_no_sig + 4, mode, 2);
    memcpy(header_no_sig + 6, salt, C3);
    memcpy(header_no_sig + 6 + C3, nonce, C4);

    f6(&hmac_ctx, mac_key, 32);
    f7(&hmac_ctx, header_no_sig, header_no_sig_len);

    memcpy(header, header_no_sig, header_no_sig_len);
    memset(header + header_no_sig_len, 0, C5);
    if (fwrite(header, 1, full_header_len, tmp) != full_header_len) {
        ret = UNICRYPTO_ERR_IO; goto cleanup;
    }

    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) {
        ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup;
    }

    do {
        size_t bytes = fread(inbuf, 1, C8, fin);
        zs.avail_in = bytes;
        zs.next_in = inbuf;
        flush = feof(fin) ? Z_FINISH : Z_NO_FLUSH;

        do {
            zs.avail_out = C8;
            zs.next_out = compbuf;
            if (deflate(&zs, flush) == Z_STREAM_ERROR) {
                ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup;
            }
            size_t have = C8 - zs.avail_out;
            if (have > 0) {
                f21(cipher_key, nonce, counter, have, keystream_buf);
                for (size_t i = 0; i < have; i++)
                    encbuf[i] = compbuf[i] ^ keystream_buf[i];
                f7(&hmac_ctx, encbuf, have);
                if (fwrite(encbuf, 1, have, tmp) != have) {
                    ret = UNICRYPTO_ERR_IO; goto cleanup;
                }
                counter += (have + 31) / 32;
            }
        } while (zs.avail_out == 0 && ret == UNICRYPTO_OK);
    } while (flush != Z_FINISH && ret == UNICRYPTO_OK);

    deflateEnd(&zs);

    f8(&hmac_ctx, sig);

    fseek(tmp, header_no_sig_len, SEEK_SET);
    if (fwrite(sig, 1, C5, tmp) != C5) {
        ret = UNICRYPTO_ERR_IO; goto cleanup;
    }

    fflush(tmp);
    fseek(tmp, 0, SEEK_END);
    tmp_size = ftell(tmp);
    fseek(tmp, 0, SEEK_SET);

    unsigned char readbuf[C8];
    while (tmp_size > 0) {
        size_t to_read = (tmp_size < (long)C8) ? (size_t)tmp_size : C8;
        if (fread(readbuf, 1, to_read, tmp) != to_read) {
            ret = UNICRYPTO_ERR_IO; goto cleanup;
        }
        if (strcmp(mode, C9) == 0) {
            if (f17(fout, readbuf, to_read) != UNICRYPTO_OK) {
                ret = UNICRYPTO_ERR_IO; goto cleanup;
            }
        } else if (strcmp(mode, C10) == 0) {
            if (f18(fout, readbuf, to_read) != UNICRYPTO_OK) {
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
    return ret;
}

/* ============================================================
 *  文件解密（公开 API，修复解压末尾丢失问题）
 * ============================================================ */
UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_file(const char *in_path, const char *out_path,
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
    char mode_flag[3];
    unsigned char *salt = NULL, *nonce = NULL;
    const unsigned char *pwd = NULL;
    size_t pwd_len = 0;
    unsigned char cipher_key[16], mac_key[32];
    unsigned char calc_sig[C5];
    unsigned char *hmac_input = NULL;
    z_stream zs;
    unsigned char outbuf[C8];
    unsigned char decbuf[C8];
    unsigned char keystream_buf[C8];
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

    if (text_len == 0) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    uint32_t first_cp;
    int n = f12(text, text_len, &first_cp);
    if (n <= 0) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    int is_zc = (first_cp >= C12 && first_cp < C12 + C11);
    int is_zh = (first_cp >= C14 && first_cp < C14 + C13);
    if (!is_zc && !is_zh) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }

    if (is_zc) ret = f14(text, text_len, &binary, &binary_len);
    else ret = f16(text, text_len, &binary, &binary_len);
    free(text); text = NULL;
    if (ret != UNICRYPTO_OK) goto cleanup;

    size_t header_no_sig_len = 4 + 2 + C3 + C4;
    size_t full_header_len = header_no_sig_len + C5;
    if (binary_len < full_header_len) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    header_no_sig = binary;
    signature = binary + header_no_sig_len;
    ciphertext = binary + full_header_len;
    cipher_len = binary_len - full_header_len;

    if (!ignore_magic && memcmp(header_no_sig, C1, 4) != 0) {
        ret = UNICRYPTO_ERR_FORMAT; goto cleanup;
    }
    memcpy(mode_flag, header_no_sig + 4, 2); mode_flag[2] = '\0';
    salt = header_no_sig + 6;
    nonce = header_no_sig + 6 + C3;

    if (strcmp(mode_flag, C9) != 0 && strcmp(mode_flag, C10) != 0) {
        ret = UNICRYPTO_ERR_UNSUPPORTED; goto cleanup;
    }

    if (!password) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    pwd = (const unsigned char*)password;
    pwd_len = strlen(password);

    ret = f19(pwd, pwd_len, salt, C3, cipher_key, mac_key);
    if (ret != UNICRYPTO_OK) goto cleanup;

    hmac_input = (unsigned char*)malloc(header_no_sig_len + cipher_len);
    if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; goto cleanup; }
    memcpy(hmac_input, header_no_sig, header_no_sig_len);
    memcpy(hmac_input + header_no_sig_len, ciphertext, cipher_len);
    f5(mac_key, 32, hmac_input, header_no_sig_len + cipher_len, calc_sig);
    free(hmac_input); hmac_input = NULL;
    if (!ignore_magic && memcmp(signature, calc_sig, C5) != 0) {
        ret = UNICRYPTO_ERR_HMAC; goto cleanup;
    }

    fout = fopen(out_path, "wb");
    if (!fout) { ret = UNICRYPTO_ERR_IO; goto cleanup; }

    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) { ret = UNICRYPTO_ERR_DECOMPRESS; goto cleanup; }

    counter = 0;
    processed = 0;
    int inf_ret = Z_OK;
    while (processed < cipher_len && inf_ret != Z_STREAM_END) {
        size_t block = C8;
        if (processed + block > cipher_len) block = cipher_len - processed;

        f21(cipher_key, nonce, counter, block, keystream_buf);
        for (size_t i = 0; i < block; i++)
            decbuf[i] = ciphertext[processed + i] ^ keystream_buf[i];

        zs.avail_in = block;
        zs.next_in = decbuf;

        do {
            zs.avail_out = C8;
            zs.next_out = outbuf;
            inf_ret = inflate(&zs, Z_NO_FLUSH);
            if (inf_ret == Z_STREAM_ERROR) {
                ret = UNICRYPTO_ERR_DECOMPRESS;
                goto cleanup;
            }
            size_t have = C8 - zs.avail_out;
            if (have > 0) {
                if (fwrite(outbuf, 1, have, fout) != have) {
                    ret = UNICRYPTO_ERR_IO;
                    goto cleanup;
                }
            }
        } while (zs.avail_in > 0 && inf_ret != Z_STREAM_END);

        processed += block;
        counter += (block + 31) / 32;
    }

    while (inf_ret != Z_STREAM_END) {
        zs.avail_out = C8;
        zs.next_out = outbuf;
        inf_ret = inflate(&zs, Z_FINISH);
        if (inf_ret == Z_STREAM_ERROR) {
            ret = UNICRYPTO_ERR_DECOMPRESS;
            goto cleanup;
        }
        size_t have = C8 - zs.avail_out;
        if (have > 0) {
            if (fwrite(outbuf, 1, have, fout) != have) {
                ret = UNICRYPTO_ERR_IO;
                goto cleanup;
            }
        }
        if (inf_ret == Z_STREAM_END) break;
        if (inf_ret != Z_OK && inf_ret != Z_BUF_ERROR) {
            ret = UNICRYPTO_ERR_DECOMPRESS;
            goto cleanup;
        }
    }
    inflateEnd(&zs);

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    free(text);
    free(binary);
    return ret;
}

/* ============================================================
 *  内存接口（公开 API）
 * ============================================================ */
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_buf(const unsigned char *input, size_t input_len,
                                                      unsigned char **output, size_t *output_len,
                                                      const char *password, const char *mode) {
    int ret = UNICRYPTO_OK;
    unsigned char *compressed = NULL;
    size_t comp_len = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *encoded = NULL;
    size_t enc_len = 0;
    unsigned char salt[C3], nonce[C4];
    unsigned char cipher_key[16], mac_key[32];
    unsigned char header_no_sig[4 + 2 + C3 + C4];
    unsigned char signature[C5];
    unsigned char *hmac_input = NULL;
    unsigned char *total_data = NULL;
    unsigned char *ks = NULL;
    size_t header_len = 4 + 2 + C3 + C4;
    size_t total = 0;
    uint32_t counter = 0;
    size_t processed = 0;

    do {
        ret = f22(input, input_len, &compressed, &comp_len);
        if (ret != UNICRYPTO_OK) break;

        if (f10(salt, C3) != UNICRYPTO_OK ||
            f10(nonce, C4) != UNICRYPTO_OK) {
            ret = UNICRYPTO_ERR_RANDOM; break;
        }

        ret = f19((const unsigned char*)password, strlen(password),
                  salt, C3, cipher_key, mac_key);
        if (ret != UNICRYPTO_OK) break;

        memcpy(header_no_sig, C1, 4);
        memcpy(header_no_sig + 4, mode, 2);
        memcpy(header_no_sig + 6, salt, C3);
        memcpy(header_no_sig + 6 + C3, nonce, C4);

        ciphertext = (unsigned char*)malloc(comp_len);
        if (!ciphertext) { ret = UNICRYPTO_ERR_MEM; break; }
        counter = 0; processed = 0;
        while (processed < comp_len) {
            size_t block = C8;
            if (processed + block > comp_len) block = comp_len - processed;
            ks = f20(cipher_key, nonce, counter, block);
            if (!ks) { ret = UNICRYPTO_ERR_MEM; break; }
            for (size_t i = 0; i < block; i++)
                ciphertext[processed + i] = compressed[processed + i] ^ ks[i];
            free(ks); ks = NULL;
            processed += block;
            counter += (block + 31) / 32;
        }
        if (ret != UNICRYPTO_OK) break;

        hmac_input = (unsigned char*)malloc(header_len + comp_len);
        if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(hmac_input, header_no_sig, header_len);
        memcpy(hmac_input + header_len, ciphertext, comp_len);
        f5(mac_key, 32, hmac_input, header_len + comp_len, signature);
        free(hmac_input); hmac_input = NULL;

        total = header_len + C5 + comp_len;
        total_data = (unsigned char*)malloc(total);
        if (!total_data) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(total_data, header_no_sig, header_len);
        memcpy(total_data + header_len, signature, C5);
        memcpy(total_data + header_len + C5, ciphertext, comp_len);

        if (strcmp(mode, C9) == 0)
            ret = f13(total_data, total, &encoded, &enc_len);
        else if (strcmp(mode, C10) == 0)
            ret = f15(total_data, total, &encoded, &enc_len);
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
    free(ks);
    return ret;
}

UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_buf(const unsigned char *input, size_t input_len,
                                                      unsigned char **output, size_t *output_len,
                                                      const char *password, int ignore_magic) {
    int ret = UNICRYPTO_OK;
    unsigned char *text = NULL;
    unsigned char *binary = NULL;
    size_t binary_len = 0;
    size_t header_no_sig_len = 4 + 2 + C3 + C4;
    size_t full_header_len = header_no_sig_len + C5;
    unsigned char *header_no_sig = NULL;
    unsigned char *signature = NULL;
    unsigned char *ciphertext = NULL;
    size_t cipher_len = 0;
    char mode_flag[3];
    unsigned char *salt = NULL, *nonce = NULL;
    const unsigned char *pwd = NULL;
    size_t pwd_len = 0;
    unsigned char cipher_key[16], mac_key[32];
    unsigned char *hmac_input = NULL;
    unsigned char calc_sig[C5];
    uint32_t counter = 0;
    size_t processed = 0;
    unsigned char *ks = NULL;
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
        int n = f12(text, input_len, &first_cp);
        if (n <= 0) { ret = UNICRYPTO_ERR_FORMAT; break; }
        int is_zc = (first_cp >= C12 && first_cp < C12 + C11);
        int is_zh = (first_cp >= C14 && first_cp < C14 + C13);
        if (!is_zc && !is_zh) { ret = UNICRYPTO_ERR_FORMAT; break; }

        if (is_zc) ret = f14(text, input_len, &binary, &binary_len);
        else ret = f16(text, input_len, &binary, &binary_len);
        free(text); text = NULL;
        if (ret != UNICRYPTO_OK) break;

        if (binary_len < full_header_len) { ret = UNICRYPTO_ERR_FORMAT; break; }
        header_no_sig = binary;
        signature = binary + header_no_sig_len;
        ciphertext = binary + full_header_len;
        cipher_len = binary_len - full_header_len;

        if (!ignore_magic && memcmp(header_no_sig, C1, 4) != 0) {
            ret = UNICRYPTO_ERR_FORMAT; break;
        }
        memcpy(mode_flag, header_no_sig + 4, 2); mode_flag[2] = '\0';
        salt = header_no_sig + 6;
        nonce = header_no_sig + 6 + C3;

        if (strcmp(mode_flag, C9) != 0 && strcmp(mode_flag, C10) != 0) {
            ret = UNICRYPTO_ERR_UNSUPPORTED; break;
        }

        if (!password) { ret = UNICRYPTO_ERR_FORMAT; break; }
        pwd = (const unsigned char*)password;
        pwd_len = strlen(password);

        ret = f19(pwd, pwd_len, salt, C3, cipher_key, mac_key);
        if (ret != UNICRYPTO_OK) break;

        hmac_input = (unsigned char*)malloc(header_no_sig_len + cipher_len);
        if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(hmac_input, header_no_sig, header_no_sig_len);
        memcpy(hmac_input + header_no_sig_len, ciphertext, cipher_len);
        f5(mac_key, 32, hmac_input, header_no_sig_len + cipher_len, calc_sig);
        free(hmac_input); hmac_input = NULL;
        if (!ignore_magic && memcmp(signature, calc_sig, C5) != 0) {
            ret = UNICRYPTO_ERR_HMAC; break;
        }

        decrypted = (unsigned char*)malloc(cipher_len);
        if (!decrypted) { ret = UNICRYPTO_ERR_MEM; break; }
        counter = 0; processed = 0;
        while (processed < cipher_len) {
            size_t block = C8;
            if (processed + block > cipher_len) block = cipher_len - processed;
            ks = f20(cipher_key, nonce, counter, block);
            if (!ks) { ret = UNICRYPTO_ERR_MEM; break; }
            for (size_t i = 0; i < block; i++)
                decrypted[processed + i] = ciphertext[processed + i] ^ ks[i];
            free(ks); ks = NULL;
            processed += block;
            counter += (block + 31) / 32;
        }
        if (ret != UNICRYPTO_OK) break;

        ret = f23(decrypted, cipher_len, &decomp_buf, &decomp_len);
        if (ret != UNICRYPTO_OK) break;

        *output = decomp_buf;
        *output_len = decomp_len;
        decomp_buf = NULL;
    } while (0);

    free(text);
    free(binary);
    free(decrypted);
    free(decomp_buf);
    free(ks);
    return ret;
}

UNICRYPTO_API void unicrypto_free(void *ptr) {
    free(ptr);
}