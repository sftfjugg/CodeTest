# -*- coding: utf-8 -*-
from tkinter import Toplevel,Menu,Frame,scrolledtext
from tkinter.filedialog import askopenfilename
from tkinter import LEFT,YES,BOTH,INSERT
from textwrap import wrap
from util.fun import md5
from IPy import IP
import base64
import os
import re

from numpy import sort

# 加载多目标类
class Loadfile():
    def __init__(self, gui):
        self.file = Toplevel(gui.root)
        self.file.title("多目标输入界面")
        self.file.geometry('700x400+650+150')
        self.file.iconbitmap('python.ico')

        # 顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "导 入", command=self.openfile)
        self.menubar.add_command(label = "清 空", command=self.clearfile)
        self.menubar.add_command(label = "添加http", command=self.addhttp)
        self.menubar.add_command(label = "添加https", command=self.addhttps)
        self.menubar.add_command(label = "base64解码", command=self.de_base64)
        self.menubar.add_command(label = "MD5加密", command=self.go_MD5)
        self.menubar.add_command(label = "去重", command=self.del_same)
        # self.menubar.add_command(label = "空字符分隔", command=self.split_null)
        #self.menubar.add_command(label = "移除末尾状态码", command=self.remove_status)
        self.menubar.add_command(label = "IP段解析", command=self.Resolve_IP)
        self.menubar.add_command(label = "空格分割结果", command=self.split_result)
        #self.menubar.add_command(label = "长字符格式化", command=self.long_Beautify)

        # 显示菜单
        self.file.config(menu = self.menubar)
        self.frmA = Frame(self.file, width=650, height=400,bg="white")
        self.frmA.pack(expand=1, fill=BOTH)
        self.TexA = scrolledtext.ScrolledText(self.frmA, font=("consolas", 10), width=74, height=19, undo = True)
        self.TexA.pack(expand=1, fill=BOTH)
        # 关联回调函数
        self.file.protocol("WM_DELETE_WINDOW", self.close)

    def hide(self):
        """
        隐藏界面
        """
        self.file.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.file.update()
        self.file.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()
        
    def openfile(self):
        default_dir = r"./"
        file_path = askopenfilename(title=u'选择文件', initialdir=(os.path.expanduser(default_dir)))
        try:
            with open(file_path, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                self.clearfile()
                for i in array: #遍历array中的每个元素
                    self.TexA.insert(INSERT, i.replace(' ',''))
        except Exception as e:
            pass
        
    def clearfile(self):
        self.TexA.delete('1.0','end')

    def addhttp(self):
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            #i = '192.168.'+i.replace('http://','').replace('https://','')
            i = 'http://'+i.replace('http://','').replace('https://','')
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1

    def addhttps(self):
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            i = 'https://'+i.replace('http://','').replace('https://','')
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1

    def de_base64(self):
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            try:
                result = base64.b64decode(i).decode()
            except Exception as e:
                result = '[-]解密失败: '+ i
            finally:
                if index == len(array):
                    self.TexA.insert(INSERT, result)
                else:
                    self.TexA.insert(INSERT, result+'\n')
                index = index+1

    def go_MD5(self):
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            try:
                result = md5(i)
            except Exception as e:
                result = '[-]加密失败: '+ i
            finally:
                if index == len(array):
                    self.TexA.insert(INSERT, result)
                else:
                    self.TexA.insert(INSERT, result+'\n')
                index = index+1

    def del_same(self):
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        array = sort(list(set(array)))
        index = 1
        for i in array:
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1


    def split_null(self):
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            try:
                result = i.split()[0]
            except Exception as e:
                pass
            finally:
                if index == len(array):
                    self.TexA.insert(INSERT, result)
                else:
                    self.TexA.insert(INSERT, result+'\n')
                index = index+1

    def long_Beautify(self, index=70, prefix="r\"", suffix="\" \\"):
        Loadfile_text = self.TexA.get('0.0','end').strip('\n')
        self.TexA.delete('1.0','end')
        
        short_str = ""
        for _str in wrap(Loadfile_text, width=index):
            short_str += prefix + _str + suffix + "\n"
            
        self.TexA.insert(INSERT, short_str)
        
    def remove_status(self):        
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            try:
                i = i.replace(re.search(r'[0-9]{3}$',i).group(), '')
            except Exception:
                pass
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1

    def Resolve_IP(self):        
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        for CIDRip in array:
            try:
                ips = IP(CIDRip)
                for ip in ips:
                    self.TexA.insert(INSERT, str(ip)+'\n')
            except Exception as e:
                self.TexA.insert(INSERT, str(e))

    def split_result(self):        
        Loadfile_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = Loadfile_text.split("\n")
        array = [i for i in array if i!='']
        for result in array:
            try:
                target = result.split(' ')[1]
                self.TexA.insert(INSERT, str(target)+'\n')
            except Exception as e:
                self.TexA.insert(INSERT, str(e))