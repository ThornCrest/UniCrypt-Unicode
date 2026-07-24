# C 语言加密库（仅限 Linux / Android）

本目录包含 UniCrypt 的 C 语言高性能实现，提供与 Python 版本完全兼容的加密/解密功能。**不兼容 Windows**，仅适用于 Linux 及 Android 环境。

## 📄 文件说明
- **`unicrypto.h`** — 公开 API 头文件，含跨平台符号可见性控制宏。
- **`UC加密库.c`** — **标准版源码**（函数名/变量名清晰，易于阅读和调试）。
- **`UC加密库混淆版.c`** — **混淆版源码**（所有符号名称被替换为 `C1`、`f1` 等无意义名称，功能与标准版完全相同，用于代码保护或防逆向）。
- **`export.map`** — 链接器版本脚本，用于精确控制动态库导出的符号（**必须与编译命令配合使用**）。

> 两个 C 文件在功能上完全等价，你可根据需要选择其一进行编译。混淆版不影响运行性能。

## 🔌 API 概要（与头文件一致）
```c
// 文件加密（mode 可选 "zc" 或 "zh"）
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_file(
    const char *in_path, const char *out_path,
    const char *password, const char *mode
);

// 文件解密（ignore_magic=1 可跳过魔术头校验，用于兼容旧版）
UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_file(
    const char *in_path, const char *out_path,
    const char *password, int ignore_magic
);

// 内存加解密（输出缓冲区需调用 unicrypto_free 释放）
UNICRYPTO_API unicrypto_error_t unicrypto_encrypt_buf(...);
UNICRYPTO_API unicrypto_error_t unicrypto_decrypt_buf(...);
UNICRYPTO_API void unicrypto_free(void *ptr);

// 错误描述
UNICRYPTO_API const char* unicrypto_strerror(unicrypto_error_t err);