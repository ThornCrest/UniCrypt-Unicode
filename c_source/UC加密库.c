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
#define MAGIC           "EN10"
#define MAGIC_LEN       4
#define SALT_LEN        16
#define NONCE_LEN       12
#define SIG_LEN         32
#define KEY_LEN         48
#define PBKDF2_ITER     600000
#define CHUNK_SIZE      65536

#define MODE_ZC         "zc"
#define MODE_ZH         "zh"

#define ZC_BASE         112
#define ZC_START        0x0300
#define ZH_BASE         256
#define ZH_START        0x4E00

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
        case UNICRYPTO_ERR_UNSUPPORTED: return "不支持的编码模式";
        default: return "未知错误";
    }
}

/* ============================================================
 *  SHA-256（全部 static）
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
 *  HMAC-SHA256（一次性计算）
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

/* ============================================================
 *  增量 HMAC-SHA256（用于流式加密）
 * ============================================================ */
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
 *  PBKDF2-HMAC-SHA256（无 malloc，返回 int）
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
 *  随机数
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
 *  UTF-8 编解码
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
 *  流式编码器（直接写入 FILE*，带错误返回）
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
 *  密钥派生与密钥流
 * ============================================================ */
static int derive_keys(const unsigned char *pass, size_t pass_len,
                       const unsigned char *salt, size_t salt_len,
                       unsigned char *cipher_key, unsigned char *mac_key) {
    unsigned char key_material[KEY_LEN];
    if (pbkdf2_hmac_sha256(pass, pass_len, salt, salt_len, PBKDF2_ITER, KEY_LEN, key_material) != 0)
        return UNICRYPTO_ERR_MEM;
    memcpy(cipher_key, key_material, 16);
    memcpy(mac_key, key_material + 16, 32);
    return UNICRYPTO_OK;
}

/* 一次性密钥流（用于内存接口） */
static unsigned char* make_keystream(const unsigned char *cipher_key,
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
        unsigned char input[NONCE_LEN + 4];
        memcpy(input, nonce, NONCE_LEN);
        memcpy(input + NONCE_LEN, cbytes, 4);
        unsigned char digest[32];
        hmac_sha256(cipher_key, 16, input, NONCE_LEN + 4, digest);
        size_t to_copy = (needed - written) < 32 ? (needed - written) : 32;
        memcpy(stream + written, digest, to_copy);
        written += to_copy;
        counter++;
    }
    return stream;
}

/* 复用缓冲区的密钥流（用于流式文件接口） */
static void make_keystream_to(const unsigned char *cipher_key,
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
        unsigned char input[NONCE_LEN + 4];
        memcpy(input, nonce, NONCE_LEN);
        memcpy(input + NONCE_LEN, cbytes, 4);
        unsigned char digest[32];
        hmac_sha256(cipher_key, 16, input, NONCE_LEN + 4, digest);
        size_t to_copy = (needed - written) < 32 ? (needed - written) : 32;
        memcpy(out + written, digest, to_copy);
        written += to_copy;
        counter++;
    }
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
 *  文件接口（加密使用单临时文件，确保输出全文本）
 * ============================================================ */
unicrypto_error_t unicrypto_encrypt_file(const char *in_path, const char *out_path,
                                         const char *password, const char *mode) {
    int ret = UNICRYPTO_OK;
    FILE *fin = NULL, *fout = NULL, *tmp = NULL;
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    unsigned char cipher_key[16], mac_key[32];
    unsigned char header_no_sig[4 + 2 + SALT_LEN + NONCE_LEN];
    unsigned char header[4 + 2 + SALT_LEN + NONCE_LEN + SIG_LEN];
    size_t header_no_sig_len = 4 + 2 + SALT_LEN + NONCE_LEN;
    size_t full_header_len = header_no_sig_len + SIG_LEN;
    unsigned char inbuf[CHUNK_SIZE];
    unsigned char compbuf[CHUNK_SIZE];
    unsigned char encbuf[CHUNK_SIZE];
    unsigned char keystream_buf[CHUNK_SIZE];
    unsigned char sig[SIG_LEN];
    z_stream zs;
    hmac_sha256_ctx hmac_ctx;
    uint32_t counter = 0;
    int flush = Z_NO_FLUSH;
    long tmp_size;

    fin = fopen(in_path, "rb");
    if (!fin) return UNICRYPTO_ERR_IO;
    fout = fopen(out_path, "wb");
    if (!fout) { fclose(fin); return UNICRYPTO_ERR_IO; }

    tmp = tmpfile();
    if (!tmp) { ret = UNICRYPTO_ERR_IO; goto cleanup; }

    if (get_random_bytes(salt, SALT_LEN) != UNICRYPTO_OK ||
        get_random_bytes(nonce, NONCE_LEN) != UNICRYPTO_OK) {
        ret = UNICRYPTO_ERR_RANDOM; goto cleanup;
    }

    ret = derive_keys((const unsigned char*)password, strlen(password),
                      salt, SALT_LEN, cipher_key, mac_key);
    if (ret != UNICRYPTO_OK) goto cleanup;

    memcpy(header_no_sig, MAGIC, 4);
    memcpy(header_no_sig + 4, mode, 2);
    memcpy(header_no_sig + 6, salt, SALT_LEN);
    memcpy(header_no_sig + 6 + SALT_LEN, nonce, NONCE_LEN);

    hmac_sha256_init(&hmac_ctx, mac_key, 32);
    hmac_sha256_update(&hmac_ctx, header_no_sig, header_no_sig_len);

    memcpy(header, header_no_sig, header_no_sig_len);
    memset(header + header_no_sig_len, 0, SIG_LEN);
    if (fwrite(header, 1, full_header_len, tmp) != full_header_len) {
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
                make_keystream_to(cipher_key, nonce, counter, have, keystream_buf);
                for (size_t i = 0; i < have; i++)
                    encbuf[i] = compbuf[i] ^ keystream_buf[i];
                hmac_sha256_update(&hmac_ctx, encbuf, have);
                if (fwrite(encbuf, 1, have, tmp) != have) {
                    ret = UNICRYPTO_ERR_IO; goto cleanup;
                }
                counter += (have + 31) / 32;
            }
        } while (zs.avail_out == 0 && ret == UNICRYPTO_OK);
    } while (flush != Z_FINISH && ret == UNICRYPTO_OK);

    deflateEnd(&zs);

    hmac_sha256_final(&hmac_ctx, sig);

    fseek(tmp, header_no_sig_len, SEEK_SET);
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
    return ret;
}

/* ============================================================
 *  解密文件（简化为只支持 zc/zh，必须提供密码）
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
    char mode_flag[3];
    unsigned char *salt = NULL, *nonce = NULL;
    const unsigned char *pwd = NULL;
    size_t pwd_len = 0;
    unsigned char cipher_key[16], mac_key[32];
    unsigned char calc_sig[SIG_LEN];
    unsigned char *hmac_input = NULL;
    z_stream zs;
    unsigned char outbuf[CHUNK_SIZE];
    unsigned char decbuf[CHUNK_SIZE];
    unsigned char keystream_buf[CHUNK_SIZE];
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

    // 解析头部
    size_t header_no_sig_len = 4 + 2 + SALT_LEN + NONCE_LEN;
    size_t full_header_len = header_no_sig_len + SIG_LEN;
    if (binary_len < full_header_len) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    header_no_sig = binary;
    signature = binary + header_no_sig_len;
    ciphertext = binary + full_header_len;
    cipher_len = binary_len - full_header_len;

    if (!ignore_magic && memcmp(header_no_sig, MAGIC, 4) != 0) {
        ret = UNICRYPTO_ERR_FORMAT; goto cleanup;
    }
    memcpy(mode_flag, header_no_sig + 4, 2); mode_flag[2] = '\0';
    salt = header_no_sig + 6;
    nonce = header_no_sig + 6 + SALT_LEN;

    // 只支持 zc 和 zh 模式
    if (strcmp(mode_flag, "zc") != 0 && strcmp(mode_flag, "zh") != 0) {
        ret = UNICRYPTO_ERR_UNSUPPORTED; goto cleanup;
    }

    if (!password) { ret = UNICRYPTO_ERR_FORMAT; goto cleanup; }
    pwd = (const unsigned char*)password;
    pwd_len = strlen(password);

    ret = derive_keys(pwd, pwd_len, salt, SALT_LEN, cipher_key, mac_key);
    if (ret != UNICRYPTO_OK) goto cleanup;

    hmac_input = (unsigned char*)malloc(header_no_sig_len + cipher_len);
    if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; goto cleanup; }
    memcpy(hmac_input, header_no_sig, header_no_sig_len);
    memcpy(hmac_input + header_no_sig_len, ciphertext, cipher_len);
    hmac_sha256(mac_key, 32, hmac_input, header_no_sig_len + cipher_len, calc_sig);
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

        make_keystream_to(cipher_key, nonce, counter, block, keystream_buf);
        for (size_t i = 0; i < block; i++)
            decbuf[i] = ciphertext[processed + i] ^ keystream_buf[i];

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
        counter += (block + 31) / 32;
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
 *  内存缓冲区接口
 * ============================================================ */
unicrypto_error_t unicrypto_encrypt_buf(const unsigned char *input, size_t input_len,
                                        unsigned char **output, size_t *output_len,
                                        const char *password, const char *mode) {
    int ret = UNICRYPTO_OK;
    unsigned char *compressed = NULL;
    size_t comp_len = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *encoded = NULL;
    size_t enc_len = 0;
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    unsigned char cipher_key[16], mac_key[32];
    unsigned char header_no_sig[4 + 2 + SALT_LEN + NONCE_LEN];
    unsigned char signature[SIG_LEN];
    unsigned char *hmac_input = NULL;
    unsigned char *total_data = NULL;
    unsigned char *ks = NULL;
    size_t header_len = 4 + 2 + SALT_LEN + NONCE_LEN;
    size_t total = 0;
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
                          salt, SALT_LEN, cipher_key, mac_key);
        if (ret != UNICRYPTO_OK) break;

        memcpy(header_no_sig, MAGIC, 4);
        memcpy(header_no_sig + 4, mode, 2);
        memcpy(header_no_sig + 6, salt, SALT_LEN);
        memcpy(header_no_sig + 6 + SALT_LEN, nonce, NONCE_LEN);

        ciphertext = (unsigned char*)malloc(comp_len);
        if (!ciphertext) { ret = UNICRYPTO_ERR_MEM; break; }
        counter = 0; processed = 0;
        while (processed < comp_len) {
            size_t block = CHUNK_SIZE;
            if (processed + block > comp_len) block = comp_len - processed;
            ks = make_keystream(cipher_key, nonce, counter, block);
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
        hmac_sha256(mac_key, 32, hmac_input, header_len + comp_len, signature);
        free(hmac_input); hmac_input = NULL;

        total = header_len + SIG_LEN + comp_len;
        total_data = (unsigned char*)malloc(total);
        if (!total_data) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(total_data, header_no_sig, header_len);
        memcpy(total_data + header_len, signature, SIG_LEN);
        memcpy(total_data + header_len + SIG_LEN, ciphertext, comp_len);

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
    free(ks);
    return ret;
}

unicrypto_error_t unicrypto_decrypt_buf(const unsigned char *input, size_t input_len,
                                        unsigned char **output, size_t *output_len,
                                        const char *password, int ignore_magic) {
    int ret = UNICRYPTO_OK;
    unsigned char *text = NULL;
    unsigned char *binary = NULL;
    size_t binary_len = 0;
    size_t header_no_sig_len = 4 + 2 + SALT_LEN + NONCE_LEN;
    size_t full_header_len = header_no_sig_len + SIG_LEN;
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
    unsigned char calc_sig[SIG_LEN];
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
        int n = utf8_decode(text, input_len, &first_cp);
        if (n <= 0) { ret = UNICRYPTO_ERR_FORMAT; break; }
        int is_zc = (first_cp >= ZC_START && first_cp < ZC_START + ZC_BASE);
        int is_zh = (first_cp >= ZH_START && first_cp < ZH_START + ZH_BASE);
        if (!is_zc && !is_zh) { ret = UNICRYPTO_ERR_FORMAT; break; }

        if (is_zc) ret = decode_zc(text, input_len, &binary, &binary_len);
        else ret = decode_zh(text, input_len, &binary, &binary_len);
        free(text); text = NULL;
        if (ret != UNICRYPTO_OK) break;

        if (binary_len < full_header_len) { ret = UNICRYPTO_ERR_FORMAT; break; }
        header_no_sig = binary;
        signature = binary + header_no_sig_len;
        ciphertext = binary + full_header_len;
        cipher_len = binary_len - full_header_len;

        if (!ignore_magic && memcmp(header_no_sig, MAGIC, 4) != 0) {
            ret = UNICRYPTO_ERR_FORMAT; break;
        }
        memcpy(mode_flag, header_no_sig + 4, 2); mode_flag[2] = '\0';
        salt = header_no_sig + 6;
        nonce = header_no_sig + 6 + SALT_LEN;

        if (strcmp(mode_flag, "zc") != 0 && strcmp(mode_flag, "zh") != 0) {
            ret = UNICRYPTO_ERR_UNSUPPORTED; break;
        }

        if (!password) { ret = UNICRYPTO_ERR_FORMAT; break; }
        pwd = (const unsigned char*)password;
        pwd_len = strlen(password);

        ret = derive_keys(pwd, pwd_len, salt, SALT_LEN, cipher_key, mac_key);
        if (ret != UNICRYPTO_OK) break;

        hmac_input = (unsigned char*)malloc(header_no_sig_len + cipher_len);
        if (!hmac_input) { ret = UNICRYPTO_ERR_MEM; break; }
        memcpy(hmac_input, header_no_sig, header_no_sig_len);
        memcpy(hmac_input + header_no_sig_len, ciphertext, cipher_len);
        hmac_sha256(mac_key, 32, hmac_input, header_no_sig_len + cipher_len, calc_sig);
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
            ks = make_keystream(cipher_key, nonce, counter, block);
            if (!ks) { ret = UNICRYPTO_ERR_MEM; break; }
            for (size_t i = 0; i < block; i++)
                decrypted[processed + i] = ciphertext[processed + i] ^ ks[i];
            free(ks); ks = NULL;
            processed += block;
            counter += (block + 31) / 32;
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
    free(ks);
    return ret;
}

void unicrypto_free(void *ptr) {
    free(ptr);
}