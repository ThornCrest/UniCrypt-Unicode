
---

### 📄 安卓C库目录 `/c_libs/README.md`

```markdown
# 安卓预编译库 (.so)

本目录存放为 **安卓四大主流 CPU 架构** 预编译好的 C 加密动态库，可直接在 **Pydroid 3** 或 Termux 等安卓 Python 环境中使用。

## 📁 目录结构
/c_libs/
├── README.md
├── arm64-v8a
├── armeabi-v7a
├── x86
└── x86_64
└── /For Android Pydroid3/       # Pydroid 3 专用调用封装脚本
└── （内含即用型 Python 脚本，自动处理架构检测和库加载）

## 🚀 快速调用（标准 ctypes 方式）
```python
import ctypes, platform
arch = 'arm64-v8a'   # 根据手机实际架构调整
lib = ctypes.CDLL(f"./c_libs/latest/{arch}.so")
lib.unicrypto_encrypt_file(b"in.txt", b"out.enc", b"mypass", b"zh")
```

📦 For Android Pydroid3 文件夹

该目录下提供了一个 专为 Pydroid 3 环境优化的调用封装，自动识别 CPU 架构、设置库路径，并提供简洁的函数接口（如 encrypt_file() / decrypt_file()），让你无需手动处理 ctypes 细节，可直接在安卓手机上运行。

🖥 与根目录 GUI 程序配合

根目录下的 加密10动态库gui版.py 是一个 Tkinter 图形界面程序，它会自动将当前目录的 libunicrypto.so 复制到 Pydroid 3 的系统库目录，并调用 C 库进行加解密。运行前请确保已将编译好的库文件（或预编译库）放在脚本同目录下。

⚠️ 注意：所有 .so 仅适用于 Android / Linux，不兼容 Windows。若加载失败，请检查文件权限和 CPU 架构（arm64-v8a 主流，armeabi-v7a 老旧设备）。