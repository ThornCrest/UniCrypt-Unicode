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

/* ---------- 编码模式常量 ---------- */
#define UNICRYPTO_MODE_ZC   "zc"   /* Base-112符号映射 */
#define UNICRYPTO_MODE_ZH   "zh"   /* 汉字映射 */

/* ---------- 算法常量 ---------- */
#define UNICRYPTO_ALGO_SHA   's'   /* SHA256+HMAC流加密（默认） */
#define UNICRYPTO_ALGO_AES   'a'   /* AES-128-CTR */
#define UNICRYPTO_ALGO_CHACHA 'c'  /* ChaCha20 */

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

/* 文件加解密（新增算法参数 algo，可选 's', 'a', 'c'） */
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_file(const char *in_path,
                                                        const char *out_path,
                                                        const char *password,
                                                        const char *mode,
                                                        char algo);

/* @param ignore_magic: 0=校验魔数(默认), 1=跳过校验(强制解密) */
UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_file(const char *in_path,
                                                        const char *out_path,
                                                        const char *password,
                                                        int ignore_magic);

/* 内存加解密（新增算法参数 algo） */
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_buf(const unsigned char *input,
                                                       size_t input_len,
                                                       unsigned char **output,
                                                       size_t *output_len,
                                                       const char *password,
                                                       const char *mode,
                                                       char algo);

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