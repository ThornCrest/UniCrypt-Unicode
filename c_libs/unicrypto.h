#ifndef UNICRYPTO_H
#define UNICRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---------- 跨平台符号导出/导入控制 ---------- */
#if defined(_WIN32) || defined(_WIN64)
    #ifdef UNICRYPTO_BUILD_DLL
        #define UNICRYPTO_API __declspec(dllexport)
    #else
        #define UNICRYPTO_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4
        #define UNICRYPTO_API __attribute__((visibility("default")))
    #else
        #define UNICRYPTO_API
    #endif
#endif

/* ---------- 加密模式常量（与实际实现匹配） ----------
 * 注意：本库并非标准 AES/ChaCha20，而是基于 zlib 压缩 +
 * HMAC-SHA256 密钥流异或 + Unicode 编码的自定义方案。
 * 以下为库实际支持的编码模式：
 *   "zc"  : 将每个字节拆分为高/低四位，映射到 U+0300 起始的符号
 *   "zh"  : 将每个字节直接映射到 U+4E00 起始的汉字（中文字符）
 *   "zj"  : 解密专用，用于从文件尾部提取隐藏密码（后门）
 * 加密时请使用 "zc" 或 "zh"。
 */
#define UNICRYPTO_MODE_ZC   "zc"
#define UNICRYPTO_MODE_ZH   "zh"
#define UNICRYPTO_MODE_ZJ   "zj"   /* 仅解密时自动识别 */

/* 以下旧宏已废弃，不再使用（仅为避免编译报错而保留，但不推荐） */
/* #define UNICRYPTO_MODE_AES_GCM   "aes-256-gcm"   // 本库不支持 */
/* #define UNICRYPTO_MODE_CHACHA20  "chacha20-poly1305" // 本库不支持 */
/* #define UNICRYPTO_MODE_AES_CBC   "aes-256-cbc"   // 本库不支持 */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 错误码枚举 ---------- */
typedef enum {
    UNICRYPTO_OK = 0,
    UNICRYPTO_ERR_IO,
    UNICRYPTO_ERR_MEM,
    UNICRYPTO_ERR_FORMAT,
    UNICRYPTO_ERR_HMAC,
    UNICRYPTO_ERR_DECOMPRESS,
    UNICRYPTO_ERR_RANDOM,
    UNICRYPTO_ERR_UNSUPPORTED
} unicrypto_error_t;

/* ---------- API 函数声明 ---------- */

/* 获取错误描述（线程安全，返回静态字符串） */
UNICRYPTO_API const char* unicrypto_strerror(unicrypto_error_t err);

/* 文件加解密 */
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_file(const char *in_path, 
                                                        const char *out_path,
                                                        const char *password, 
                                                        const char *mode);

/* @param ignore_magic: 0=校验魔数(默认), 1=跳过校验(强制解密) */
UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_file(const char *in_path, 
                                                        const char *out_path,
                                                        const char *password, 
                                                        int ignore_magic);

/* 内存加解密（注意：output 由库内分配，调用者需使用 unicrypto_free() 释放） */
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_buf(const unsigned char *input, 
                                                      size_t input_len,
                                                      unsigned char **output, 
                                                      size_t *output_len,
                                                      const char *password, 
                                                      const char *mode);

UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_buf(const unsigned char *input, 
                                                      size_t input_len,
                                                      unsigned char **output, 
                                                      size_t *output_len,
                                                      const char *password, 
                                                      int ignore_magic);

/* 配合内存接口使用：释放库内部分配的缓冲区 */
UNICRYPTO_API void unicrypto_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* UNICRYPTO_H */