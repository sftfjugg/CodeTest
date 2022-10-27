from tkinter import messagebox,Toplevel,Menu,Frame,scrolledtext
from tkinter import LEFT,YES,BOTH,INSERT,END
from keyword import kwlist
import importlib
import string
import os

try:
    from idlelib.colorizer import ColorDelegator
    from idlelib.percolator import Percolator
#可能未安装IDLE
except ImportError:
    ColorDelegator = Percolator = None

#内置函数
bifs = dir(__builtins__)
#关键字
kws = kwlist
#编辑代码界面类
class CodeFile():
    def __init__(self, root, file_name, Logo, vuln_select, text=''):
        if Logo == '2':
            self.file_name1 = './EXP/' + file_name + '.py'
        else:
            self.file_name1 = './POC/' + file_name + '.py'
        if os.path.exists(self.file_name1) == False:
            messagebox.showinfo(title='提示', message='还未选择模块')
            return
        self.vuln_select = vuln_select
        self.file_name = file_name
        self.file = Toplevel(root)
        self.file.title("文本编辑")
        self.file.geometry('900x500+1150+150')
        self.file.iconbitmap('python.ico')
        #定位字符
        self.text = 'def '+text
        #
        self.colorobj = self._codefilter = None
        #顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "保 存", accelerator="ctrl + s", command=lambda :self.save_file('1',self.vuln_select))
        self.menubar.add_command(label = "撤 销", accelerator="Ctrl + Z", command=self.move)
        self.menubar.add_command(label = "Dnslog", command=self.switch_Dnslog)
        self.menubar.add_command(label = "Ceye", command=self.switch_Ceye)
        
        self.file.bind("<Control-s>",lambda event:self.save_file('1',self.vuln_select))

        #显示菜单
        self.file.config(menu = self.menubar)

        self.frmA = Frame(self.file, width=900, height=500,bg="white")
        self.frmA.pack(fill=BOTH, expand=1)

        self.TexA = scrolledtext.ScrolledText(self.frmA,font=("consolas", 9),undo = True)
        self.TexA.pack(fill=BOTH, expand=1)
        self.TexA.bind('<KeyRelease>', self.process_key)

        self.TexA.tag_config('bif', foreground='orange')
        self.TexA.tag_config('kw', foreground='purple')
        self.TexA.tag_config('comment', foreground='red')
        self.TexA.tag_config('string', foreground='green')

        self.openRender()
        #渲染颜色
        self.change_mode()

    def switch_Dnslog(self):
        Loadfile_text = self.TexA.get('0.0','end').strip('\n')
        self.TexA.delete('1.0','end')
        Loadfile_text = Loadfile_text.replace('Ceye', 'Dnslog')
        self.TexA.insert(INSERT, Loadfile_text)
        
    def switch_Ceye(self):
        Loadfile_text = self.TexA.get('0.0','end').strip('\n')
        self.TexA.delete('1.0','end')
        Loadfile_text = Loadfile_text.replace('Dnslog', 'Ceye')
        self.TexA.insert(INSERT, Loadfile_text)

    def move(self):
        self.TexA.edit_undo()

    def change_mode(self):
        if ColorDelegator:
            #设置代码高亮显示
            self._codefilter=ColorDelegator()
            if not self.colorobj:
                self.colorobj=Percolator(self.TexA)
            self.colorobj.insertfilter(self._codefilter)

    def openRender(self):
        try:
            with open(self.file_name1, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                for i in array: #遍历array中的每个元素
                    self.TexA.insert(INSERT, i)
            if self.text and self.text != 'ALL' and self.text != 'def ':
                idx = '1.0'
                idx = self.TexA.search(self.text, idx, nocase=1, stopindex=END)
                if idx:
                    #跳转到指定行
                    self.TexA.see(idx)
                    lineinfo=self.TexA.dlineinfo(idx)
                    self.TexA.yview_scroll(lineinfo[1], 'pixels')
                    #self.TexA.mark_set('insert', idx.split('.')[0]+'.0')
            #self.color_render()
        except FileNotFoundError:
            print('[-]还未选择模块,无法编辑')
        except Exception as e:
            messagebox.showerror(title='结果', message=e)

    def color_render(self):
        current_line_num, current_col_num = map(int, self.TexA.index(INSERT).split('.'))
        lines = self.TexA.get('0.0', END).rstrip('\n').splitlines(keepends=True)
        #删除原来的内容
        self.TexA.delete('0.0', END)
        for line in lines:
            #flag1表示当前是否处于单词中
            #flag2表示当前是否处于双引号的包围范围之内
            #flag3表示当前是否处于单引号的包围范围之内
            flag1, flag2, flag3 = False, False, False
            for index, ch in enumerate(line):
                #单引号和双引号优先
                if ch == "'" and not flag2:
                    #左右引号之间切换
                    flag3 = not flag3
                    self.TexA.insert(INSERT, ch, 'string')
                elif ch == '"' and not flag3:
                    flag2 = not flag2
                    self.TexA.insert(INSERT, ch, 'string')
                #引号之内, 直接绿色显示
                elif flag2 or flag3:
                    self.TexA.insert(INSERT, ch, 'string')
                else:
                    #当前字符不是字母
                    if ch not in string.ascii_letters:
                        #但是前一个字符是字母,说明一个单词结束
                        if flag1:
                            flag1 = False
                            #获取该位置前面的最后一个单词
                            word = line[start:index]
                            #内置函数, 加标记
                            if word in bifs:
                                self.TexA.insert(INSERT, word, 'bif')
                            #关键字,加标记
                            elif word in kws:
                                self.TexA.insert(INSERT, word, 'kw')
                            else:
                                self.TexA.insert(INSERT, word)
                        #单行注释，加标记，这一行后面的字符不再处理，全部作为注释内容
                        if ch == '#':
                            self.TexA.insert(INSERT, line[index:], 'comment')
                            break
                        else:
                            self.TexA.insert(INSERT, ch)
                    else:
                        #一个新单词的开始
                        if not flag1:
                            flag1 = True
                            start = index
            #考虑该行最后一个字符是字母的情况
            #正在输入的当前行最后一个字符大部分情况下是字母
            if flag1:
                flag1 = False
                word = line[start:]
                if word in bifs:
                    self.TexA.insert(INSERT, word, 'bif')
                elif word in kws:
                    self.TexA.insert(INSERT, word, 'kw')
                else:
                    self.TexA.insert(INSERT, word)
        #原来的内容重新着色以后，光标位置会在文本框最后
        #这一行用来把光标位置移动到指定的位置，也就是正在修改的位置
        self.TexA.mark_set('insert', f'{current_line_num}.{current_col_num}')
        

    def save_file(self,event,vuln_select):
        #if messagebox.askokcancel('提示','要执行此操作吗?') == True:
        if vuln_select == None:
            self.file.destroy()
            messagebox.showinfo(title='提示', message='还未选择模块')
            return
        save_data = str(self.TexA.get('0.0','end'))
        try:
            fobj_w = open(self.file_name1, 'w', encoding='utf-8')
            fobj_w.writelines(save_data.strip('\n'))
            fobj_w.close()
            #self.openRender()
            vuln_select = importlib.reload(vuln_select)
            #vuln = importlib.import_module('.%s'%self.file_name,package='EXP')
            #messagebox.showinfo(title='结果', message='保存成功')
            print('[*]保存成功,%s模块已重新载入!'%self.file_name)
        except Exception as e:
            print("异常对象的内容是%s"%e)
            #print(self.file_name1)
            messagebox.showerror(title='结果', message='出现错误')
        
    def process_key(self,key):
        current_line_num, current_col_num = map(int, self.TexA.index(INSERT).split('.'))
        if key.keycode == 13:
            last_line_num = current_line_num - 1
            last_line = self.TexA.get(f'{last_line_num}.0', INSERT).rstrip()
            #计算最后一行的前导空格数量
            num = len(last_line) - len(last_line.lstrip(' '))
            #最后一行以冒号结束，或者冒号后面有#单行注释
            if (last_line.endswith(':') or
                (':' in last_line and last_line.split(':')[-1].strip().startswith('#'))):
                num = num + 4
            elif last_line.strip().startswith(('return','break','continue','pass','raise')):
                num = num - 4
            self.TexA.insert(INSERT,' '*num)
        #按下退格键BackSpace
        
        elif key.keysym == 'BackSpace':
            #当前行从开始到鼠标位置的内容
            current_line = self.TexA.get(f'{current_line_num}.0',f'{current_line_num}.{current_col_num}')
            #当前光标位置前面的空格数量
            num = len(current_line) - len(current_line.rstrip(' '))
            #最多删除4个空格
            #这段代码是按下退格键删除了一个字符之后才执行的，所以还需要再删除最多3个空格
            num = min(4,num)
            if num > 1 and num != 4:
                self.TexA.delete(f'{current_line_num}.{current_col_num-num}',f'{current_line_num}.{current_col_num}')   
        """
        else:
            lines = self.TexA.get('0.0', END).rstrip('\n').splitlines(keepends=True)
            #删除原来的内容
            self.TexA.delete('0.0', END)
            for line in lines:
                #flag1表示当前是否处于单词中
                #flag2表示当前是否处于双引号的包围范围之内
                #flag3表示当前是否处于单引号的包围范围之内
                flag1, flag2, flag3 = False, False, False
                for index, ch in enumerate(line):
                    #单引号和双引号优先
                    if ch == "'" and not flag2:
                        #左右引号之间切换
                        flag3 = not flag3
                        self.TexA.insert(INSERT, ch, 'string')
                    elif ch == '"' and not flag3:
                        flag2 = not flag2
                        self.TexA.insert(INSERT, ch, 'string')
                    #引号之内, 直接绿色显示
                    elif flag2 or flag3:
                        self.TexA.insert(INSERT, ch, 'string')
                    else:
                        #当前字符不是字母
                        if ch not in string.ascii_letters:
                            #但是前一个字符是字母,说明一个单词结束
                            if flag1:
                                flag1 = False
                                #获取该位置前面的最后一个单词
                                word = line[start:index]
                                #内置函数, 加标记
                                if word in bifs:
                                    self.TexA.insert(INSERT, word, 'bif')
                                #关键字,加标记
                                elif word in kws:
                                    self.TexA.insert(INSERT, word, 'kw')
                                else:
                                    self.TexA.insert(INSERT, word)
                            #单行注释，加标记，这一行后面的字符不再处理，全部作为注释内容
                            if ch == '#':
                                self.TexA.insert(INSERT, line[index:], 'comment')
                                break
                            else:
                                self.TexA.insert(INSERT, ch)
                        else:
                            #一个新单词的开始
                            if not flag1:
                                flag1 = True
                                start = index
                #考虑该行最后一个字符是字母的情况
                #正在输入的当前行最后一个字符大部分情况下是字母
                if flag1:
                    flag1 = False
                    word = line[start:]
                    if word in bifs:
                        self.TexA.insert(INSERT, word, 'bif')
                    elif word in kws:
                        self.TexA.insert(INSERT, word, 'kw')
                    else:
                        self.TexA.insert(INSERT, word)
            #原来的内容重新着色以后，光标位置会在文本框最后
            #这一行用来把光标位置移动到指定的位置，也就是正在修改的位置
            self.TexA.mark_set('insert', f'{current_line_num}.{current_col_num}')    
        """