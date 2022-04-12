from tkinter import Toplevel,Menu,Frame,scrolledtext
from tkinter.filedialog import askopenfilename
from tkinter import LEFT,YES,BOTH,INSERT
from textwrap import wrap
import base64
import os
import re

#加载多目标类
class Loadfile():
    def __init__(self, gui):
        self.file = Toplevel(gui.root)
        self.file.title("多目标输入界面")
        self.file.geometry('700x400+650+150')
        self.file.iconbitmap('python.ico')

        #顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "导 入", command=self.openfile)
        self.menubar.add_command(label = "清 空", command=self.clearfile)
        self.menubar.add_command(label = "添加http", command=self.addhttp)
        self.menubar.add_command(label = "添加https", command=self.addhttps)
        self.menubar.add_command(label = "base64解码", command=self.de_base64)
        self.menubar.add_command(label = "空字符分隔", command=self.split_null)
        self.menubar.add_command(label = "移除末尾状态码", command=self.remove_status)
        #self.menubar.add_command(label = "长字符格式化", command=self.long_Beautify)

        #显示菜单
        self.file.config(menu = self.menubar)
        self.frmA = Frame(self.file, width=650, height=400,bg="white")
        self.frmA.rowconfigure(0,weight=1)
        self.frmA.columnconfigure(0,weight=1)
        self.frmA.pack(fill=BOTH, expand=1)

        self.TexA = scrolledtext.ScrolledText(self.frmA,font=("consolas",9),width=74,height=19, undo = True)
        self.TexA.pack(fill=BOTH, expand=1)

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