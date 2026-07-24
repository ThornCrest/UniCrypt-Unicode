#!/usr/bin/env python3
_C='zh'
_B='encrypt'
_A='utf-8'
import os,sys,shutil,ctypes
from ctypes import c_char_p,c_int
import tkinter as tk
from tkinter import filedialog,messagebox,ttk
UNICRYPTO_OK=0
UNICRYPTO_ERR_IO=1
UNICRYPTO_ERR_MEM=2
UNICRYPTO_ERR_FORMAT=3
UNICRYPTO_ERR_HMAC=4
UNICRYPTO_ERR_DECOMPRESS=5
UNICRYPTO_ERR_RANDOM=6
UNICRYPTO_ERR_UNSUPPORTED=7
MODE_ZC='zc'
MODE_ZH=_C
def load_library():
	F='libunicrypto.so';G=os.path.dirname(os.path.abspath(__file__));B=os.path.join(G,F)
	if not os.path.exists(B):
		B=os.path.abspath('./libunicrypto.so')
		if not os.path.exists(B):raise RuntimeError('当前目录下未找到 libunicrypto.so，请将库文件放在脚本同目录。')
	E='/data/data/ru.iiec.pydroid3/files';C=os.path.join(E,F);os.makedirs(E,exist_ok=True)
	try:shutil.copy2(B,C);os.chmod(C,493);print(f"✅ 已更新库: {B} -> {C}")
	except Exception as D:raise RuntimeError(f"复制库文件失败: {D}")
	try:A=ctypes.CDLL(C);A.unicrypto_encrypt_file.argtypes=[c_char_p,c_char_p,c_char_p,c_char_p];A.unicrypto_encrypt_file.restype=c_int;A.unicrypto_decrypt_file.argtypes=[c_char_p,c_char_p,c_char_p,c_int];A.unicrypto_decrypt_file.restype=c_int;A.unicrypto_strerror.argtypes=[c_int];A.unicrypto_strerror.restype=c_char_p;return A
	except OSError as D:raise RuntimeError(f"加载库失败: {D}")
def encrypt_file_c(lib,in_path,out_path,password,mode):
	A=out_path;B=lib.unicrypto_encrypt_file(in_path.encode(_A),A.encode(_A),password.encode(_A),mode.encode(_A))
	if B!=UNICRYPTO_OK:C=lib.unicrypto_strerror(B).decode(_A);raise RuntimeError(f"加密失败 (错误码 {B}): {C}")
	if not os.path.exists(A)or os.path.getsize(A)==0:raise RuntimeError('加密返回成功，但输出文件不存在或大小为 0，可能写入权限不足。')
def decrypt_file_c(lib,in_path,out_path,password,ignore_magic):
	C=password;A=out_path;B=lib.unicrypto_decrypt_file(in_path.encode(_A),A.encode(_A),C.encode(_A)if C else b'',ignore_magic)
	if B!=UNICRYPTO_OK:D=lib.unicrypto_strerror(B).decode(_A);raise RuntimeError(f"解密失败 (错误码 {B}): {D}")
	if not os.path.exists(A)or os.path.getsize(A)==0:raise RuntimeError('解密返回成功，但输出文件不存在或大小为 0，可能写入权限不足。')
class App:
	def __init__(A,root,lib):B=False;A.lib=lib;A.root=root;A.root.title('Unicode 加密工具 (C 库版)');A.root.resizable(B,B);A.mode=tk.StringVar(value=_B);A.enc_mode=tk.StringVar(value=_C);A.input_path=tk.StringVar();A.output_path=tk.StringVar();A.password=tk.StringVar();A.ignore_magic=tk.IntVar(value=0);A.create_widgets()
	def create_widgets(A):D='浏览...';B='w';C=ttk.LabelFrame(A.root,text='操作模式',padding=5);C.grid(row=0,column=0,columnspan=4,padx=10,pady=5,sticky='ew');ttk.Radiobutton(C,text='加密',variable=A.mode,value=_B,command=A.update_mode).grid(row=0,column=0,padx=5);ttk.Radiobutton(C,text='解密',variable=A.mode,value='decrypt',command=A.update_mode).grid(row=0,column=1,padx=5);A.enc_mode_label=ttk.Label(C,text='加密模式:');A.enc_mode_label.grid(row=0,column=2,padx=5);A.enc_mode_combo=ttk.Combobox(C,textvariable=A.enc_mode,values=['zh (汉字编码)','zc (Base-112)'],state='readonly',width=18);A.enc_mode_combo.grid(row=0,column=3,padx=5);tk.Label(A.root,text='输入文件:').grid(row=1,column=0,padx=5,pady=5,sticky=B);tk.Entry(A.root,textvariable=A.input_path,width=50).grid(row=1,column=1,padx=5,pady=5);tk.Button(A.root,text=D,command=A.browse_input).grid(row=1,column=2,padx=5,pady=5);tk.Label(A.root,text='输出文件:').grid(row=2,column=0,padx=5,pady=5,sticky=B);tk.Entry(A.root,textvariable=A.output_path,width=50).grid(row=2,column=1,padx=5,pady=5);tk.Button(A.root,text=D,command=A.browse_output).grid(row=2,column=2,padx=5,pady=5);tk.Label(A.root,text='密码:').grid(row=3,column=0,padx=5,pady=5,sticky=B);tk.Entry(A.root,textvariable=A.password,width=50,show='*').grid(row=3,column=1,padx=5,pady=5);A.ignore_frame=ttk.Frame(A.root);A.ignore_frame.grid(row=4,column=0,columnspan=4,padx=5,pady=5,sticky=B);A.ignore_check=ttk.Checkbutton(A.ignore_frame,text='忽略魔数校验 (强制解密)',variable=A.ignore_magic);A.ignore_check.pack(anchor=B);A.run_button=tk.Button(A.root,text='执行',command=A.run);A.run_button.grid(row=5,column=1,padx=5,pady=10);A.status=tk.Label(A.root,text='就绪',relief='sunken',anchor=B);A.status.grid(row=6,column=0,columnspan=3,padx=5,pady=5,sticky='ew');A.update_mode()
	def update_mode(A):
		if A.mode.get()==_B:A.enc_mode_label.grid();A.enc_mode_combo.grid();A.ignore_frame.grid_remove()
		else:A.enc_mode_label.grid_remove();A.enc_mode_combo.grid_remove();A.ignore_frame.grid()
		A.suggest_output()
	def browse_input(A):
		B=filedialog.askopenfilename(title='选择输入文件')
		if B:A.input_path.set(B);A.suggest_output()
	def browse_output(B):
		A=filedialog.asksaveasfilename(title='选择输出文件')
		if A:B.output_path.set(A)
	def suggest_output(B):
		F='-dec';E='-enc';C=B.input_path.get()
		if not C:return
		G=os.path.dirname(C);A=os.path.basename(C)
		if B.mode.get()==_B:D=A+E
		elif A.endswith(E):D=A[:-4]+F
		else:D=A+F
		B.output_path.set(os.path.join(G,D))
	def run(A):
		I='魔术头不匹配';B='错误';E=A.input_path.get().strip();C=A.output_path.get().strip()
		if not E:messagebox.showerror(B,'请选择输入文件');return
		if not C:messagebox.showerror(B,'请指定输出文件');return
		if not os.path.isfile(E):messagebox.showerror(B,'输入文件不存在');return
		try:
			A.status.config(text='正在处理...');A.root.update()
			if A.mode.get()==_B:
				F=A.password.get()
				if not F:messagebox.showerror(B,'加密需要输入密码');return
				J=A.enc_mode.get()
				if J.startswith(_C):G=_C
				else:G='zc'
				encrypt_file_c(A.lib,E,C,F,G);H=f"加密完成（{G.upper()}模式）！\n输出文件：{C}"
			else:F=A.password.get()if A.password.get()else None;K=bool(A.ignore_magic.get());decrypt_file_c(A.lib,E,C,F,K);H=f"解密完成！\n输出文件：{C}"
			A.status.config(text='完成');messagebox.showinfo('成功',H)
		except RuntimeError as D:
			A.status.config(text=B)
			if I in str(D)or'UNICRYPTO_ERR_FORMAT'in str(D):
				if messagebox.askyesno(I,'文件魔术头不匹配，可能是旧版本或损坏文件。\n是否尝试忽略魔术头并强制解密？'):
					try:decrypt_file_c(A.lib,E,C,F,True);messagebox.showinfo('成功',f"强制解密完成！\n输出文件：{C}");A.status.config(text='完成')
					except Exception as L:messagebox.showerror(B,str(L));A.status.config(text=B)
				else:messagebox.showerror(B,str(D))
			else:messagebox.showerror(B,str(D))
		except Exception as D:A.status.config(text=B);messagebox.showerror(B,str(D))
def main():
	try:B=load_library()
	except Exception as C:tk.Tk().withdraw();messagebox.showerror('库加载失败',str(C));sys.exit(1)
	A=tk.Tk();D=App(A,B);A.mainloop()
if __name__=='__main__':main()