# UniCrypt-Unicode

**项目目的**  
将任意文件（文本、图片、程序等）通过高强度加密流程（zlib压缩 → 流式异或加密 → HMAC-SHA256签名）/AES-128-CTR/ChaCha20后，编码为 **Unicode 特殊字符**（U+0300~U+036F）或 **汉字**（U+4E00~U+4EFF）文本。加密后的文件完全由可见字符组成，便于在纯文本环境（如邮件、聊天、代码注释）中隐蔽传输或存储。

**特别说明**  
- 本仓库所有 Python 及 C 代码 **99% 由 AI 生成**，本人仅做整合与测试，不喜勿喷，欢迎 fork 改进。
- Python 版本的加密逻辑（不含隐写加载器）**s模式无需任何第三方库**，仅依赖 Python 标准库（`os`, `zlib`, `hashlib`, `hmac`, `argparse`, `tkinter` 等），开箱即用，a模式（AES-128-CTR）和c模式（ChaCha20）需要pycryptodome额外库。
- **⚠️ 已知问题**：早期版本（v1~v4）中，**若加密时不勾选压缩（`compress=False`），生成的加密文件将无法解密**。此 bug 已在 v7 及以后版本修复（强制启用压缩）。因此请务必使用 v7+ 版本，或始终开启压缩。
- **C 库版本**：提供标准版和混淆版两种源码（功能相同，混淆版用于代码保护），并附带一个 **Python GUI 封装程序**（`加密10动态库gui版.py`），可直接调用 C 动态库进行加解密，适合安卓 Pydroid 3 环境。
- 推荐加密文件大小不超过50mb否则可能时间过长
## ✨ 核心特性

- **跨平台**：Python 版支持 Windows / Linux / Android（Termux / Pydroid 3），C 库版支持 Linux / Android。
- **零依赖（SHA256 模式）**：v10 及 v11 的 SHA256 模式仅依赖 Python 标准库，无需安装任何第三方包。
- **多算法支持（v11 新特性）**：
  - `SHA256`（默认）—— 原版 HMAC-SHA256 密钥流，无需额外库。
  - `AES-128-CTR` —— 需安装 `pycryptodome`。
  - `ChaCha20` —— 需安装 `pycryptodome`。
- **两种编码模式**：
  - `zc` —— Base-112 编码到 U+0300~U+036F（兼容性优先）。
  - `zh` —— 汉字编码到 U+4E00~U+4EFF（压缩比优先）。
- **流式处理**：支持超大文件（>4GB），内存占用恒定（64KB 缓冲区）。
- **身份验证**：HMAC-SHA256 签名防篡改，解密时自动校验。
- **向下兼容**：v11 可解密 v10 及更早版本生成的加密文件。
- 📦 依赖说明

版本 算法 依赖
v10 及更早 SHA256 无（仅 Python 标准库）
v11 SHA256（默认） 无（仅 Python 标准库）
v11 AES-128-CTR pycryptodome（pip install pycryptodome）
v11 ChaCha20 pycryptodome（pip install pycryptodome）

GUI 模式（--gui）需 tkinter（通常 Python 自带）。
v5/v6 隐写加载器需 Pillow 和 requests（仅限特殊用途）。
## 📁 文件夹分布
- **`/python/`**  
  存放所有 Python 历史版本（v1~v11），每个版本独立文件，附带版本特性说明。

- **`/c_source/`**  
  C 语言源码（标准版 + 混淆版）、头文件以及编译所需的符号导出脚本。**仅支持 Linux / Android**，编译参数已优化至最佳性能。

- **`/c_libs/`**  
  为安卓四大平台（arm64-v8a, armeabi-v7a, x86, x86_64）预编译好的动态库（`.so`），可直接在 Pydroid 3 或其他安卓 Python 环境中调用。

> 💡 **快速上手**：  
> - 纯 Python 用户：使用 `/python/UC加密11.py`（稳定版）。  
> - 想使用 C 库加速：编译 `/c_source/` 中的源码，或直接使用 `/c_libs/` 中的预编译库，再运行 `加密10动态库gui版.py` 即可获得图形界面。
