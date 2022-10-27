# -*- coding: utf-8 -*-
from tkinter import Button,Frame,Menu,LabelFrame,messagebox
from tkinter import TOP,BOTH
import subprocess
import glob
import os

class Tools():
    def __init__(self, gui):
        self.frmtools = gui.frmtools
        self.root = gui.root
        # 创建一个菜单
        self.menubar = Menu(self.root, tearoff=False)

    def CreateFrm(self):
        # 创建顶级菜单
        self.frm = Frame(self.frmtools, width=1160, height=700, bg='whitesmoke')
        # pack布局
        self.frm.pack(expand=1, fill=BOTH)
        
        self.frame_1 = LabelFrame(self.frm, text="webshell", labelanchor="nw", width=1150, bg='whitesmoke')
        self.frame_2 = LabelFrame(self.frm, text="信息探测", labelanchor="nw", width=1150, bg='whitesmoke')
        self.frame_3 = LabelFrame(self.frm, text="漏洞利用", labelanchor="nw", width=1150, bg='whitesmoke')
        self.frame_4 = LabelFrame(self.frm, text="其他工具", labelanchor="nw", width=1150, bg='whitesmoke')
        self.frame_5 = LabelFrame(self.frm, text="数据库利用", labelanchor="nw", width=1150, bg='whitesmoke')
        
        self.frame_1.pack(side=TOP, fill=BOTH, expand=True, padx=2, pady=2)
        # self.frame_2.pack(side=TOP, fill=BOTH, expand=True, padx=2, pady=2)
        self.frame_3.pack(side=TOP, fill=BOTH, expand=True, padx=2, pady=2)
        # self.frame_4.pack(side=TOP, fill=BOTH, expand=True, padx=2, pady=2)
        self.frame_5.pack(side=TOP, fill=BOTH, expand=True, padx=2, pady=2)

    def creatButton(self):
        a1 = 0
        b1 = 0
        
        a2 = 0
        b2 = 0
        
        a3 = 0
        b3 = 0
        
        a4 = 0
        b4 = 0

        a5 = 0
        b5 = 0
        for _ in glob.glob('tools/*.bat'):
            try:
                tool_all_name = os.path.basename(_).replace('.bat', '')
                tool_type = tool_all_name.split('_')[0]
                tool_name = tool_all_name.replace(tool_type+'_', '')
                
                if tool_type == 'webshell':
                    Button(self.frame_1, text=tool_name, command=lambda bat_path=tool_all_name:self.tool_click(bat_path)).grid(row=a1, column=b1, sticky="nsew", padx=3, pady=3)
                    a1 += 1
                    if a1 > 2:
                        a1 = 0
                        b1 += 1
                        
                elif tool_type == '信息探测':
                    Button(self.frame_2, text=tool_name, command=lambda bat_path=tool_all_name:self.tool_click(bat_path)).grid(row=a2, column=b2, sticky="nsew", padx=3, pady=3)
                    a2 += 1
                    if a2 > 2:
                        a2 = 0
                        b2 += 1
                        
                elif tool_type == '漏洞利用':
                    Button(self.frame_3, text=tool_name, command=lambda bat_path=tool_all_name:self.tool_click(bat_path)).grid(row=a3, column=b3, sticky="nsew", padx=3, pady=3)
                    a3 += 1
                    if a3 > 2:
                        a3 = 0
                        b3 += 1
                    
                elif tool_type == '其他工具':
                    Button(self.frame_4, text=tool_name, command=lambda bat_path=tool_all_name:self.tool_click(bat_path)).grid(row=a4, column=b4, sticky="nsew", padx=3, pady=3)
                    a4 += 1
                    if a4 > 2:
                        a4 = 0
                        b4 += 1

                elif tool_type == '数据库利用':
                    Button(self.frame_5, text=tool_name, command=lambda bat_path=tool_all_name:self.tool_click(bat_path)).grid(row=a5, column=b5, sticky="nsew", padx=3, pady=3)
                    a5 += 1
                    if a5 > 2:
                        a5 = 0
                        b5 += 1
                else:
                    continue
            except Exception as e:
                messagebox.showerror(title='错误', message=str(e))
                continue

    def tool_click(self, bat_path):
        subprocess.Popen("cd tools && "+bat_path+".bat", shell=True)

    def start(self):
        self.CreateFrm()
        self.creatButton()