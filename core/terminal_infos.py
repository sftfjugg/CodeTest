from settings import Ent_B_Bottom_terminal_cmd,Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_thread_pool
from ClassCongregation import TextRedirector
from tkinter import Toplevel,scrolledtext,Entry
from settings import rootPath
import util.globalvar as GlobalVar
import importlib
import threading
import sys
import os

class Terminal_Infos:
    running_space={'__name__':'__console__'}#运行空间(用于存储变量的)
    exec('''def print(*value):
    return None
def input(*value):
    return None
def set(*value):
    return None
def Back(*value):
    pass
del input,print,set,Back''',running_space)#先把那些Python基础函数替换了
    input_list=[]#这个是输入命令记载输入命令的列表
    pos = None
    vuln = None
    def __init__(self, root, Text_note,**kwargs):
        #目标地址
        self.target = kwargs['target']
        #脚本信息
        self.appName = kwargs['appName']
        #漏洞信息
        self.pocname = kwargs['pocname']
        #漏洞仓库的文本框
        self.Text_note = Text_note
        
        self.Terminal = Toplevel(root)
        #新建Text控件
        self.title = self.Terminal.title('命令执行终端')#设置title
        self.Terminal.iconbitmap(rootPath+'/python.ico')
        self.TerminalText = scrolledtext.ScrolledText(self.Terminal,width=120,height=30,state='d',fg='white',bg='black',insertbackground='white',font=('consolas',10),selectforeground='black',selectbackground='white',takefocus=False)
        self.TerminalText.pack(fill='both', expand=1)

        #实现不同颜色的效果，用于insert插入标记
        self.TerminalText.tag_config('red',foreground='red',selectforeground='#00ffff',selectbackground='#ffffff')
        self.TerminalText.tag_config('green',foreground='green',selectforeground='#ff7eff',selectbackground='#ffffff')
        self.TerminalText.tag_config('blue',foreground='blue',selectforeground='#ffff7e',selectbackground='#ffffff')
        self.TerminalText.tag_config('cyan',foreground='cyan',selectforeground='red',selectbackground='#ffffff')

        self.TerminalText['state']='n'
        self.TerminalText.insert('end', f'{os.getcwd()}'+':~# ', 'green')

        #命令输入框
        self.command_input = Entry(self.TerminalText,font=('consolas',10),textvariable=Ent_B_Bottom_terminal_cmd,fg='white',bg='black',insertbackground='white',selectforeground='black',selectbackground='white',relief='flat',width=104)
        self.command_input.bind('<Key-Return>',lambda v=0:self.run_command(self.command_input.get(),self.TerminalText,self.command_input))
        self.command_input.bind('<Key-Up>', lambda v=0:self.CmdbackUp(Ent_B_Bottom_terminal_cmd))
        self.command_input.bind('<Key-Down>', lambda v=0:self.CmdbackDown(Ent_B_Bottom_terminal_cmd))
        #在命令输入框中按F7弹出命令列表窗口
        #self.command_input.bind('<F7>',lambda v=0:self.post_inputlist(self.command_input))
        self.TerminalText.bind('<Key-Return>',lambda v=0:self.contiune_command())
        #插入命令输入框
        self.TerminalText.window_create('end', window=self.command_input)

        #让终端Text不可编辑
        #self.TerminalText['state']='d'

        sys.stdout = TextRedirector(self.TerminalText, "stdout", index="2")
        sys.stderr = TextRedirector(self.TerminalText, "stderr", index="2")
        self.Terminal.protocol("WM_DELETE_WINDOW", self.callbackClose)
        
    def CmdbackUp(self, entry_cmd_text):
        try:
            if Terminal_Infos.pos is None:
                pos = len(Terminal_Infos.input_list) - 1
            elif Terminal_Infos.pos == 0:
                return
            else:
                pos = Terminal_Infos.pos
            pos -= 1
            entry_cmd_text.set('')
            self.command_input.insert('end', Terminal_Infos.input_list[pos])
            Terminal_Infos.pos = pos#记录位置
            #self.command_input.xview_moveto(1)
        except Exception:
            pass
        finally:
            self.command_input.focus_set()

    def CmdbackDown(self, entry_cmd_text):
        try:
            if Terminal_Infos.pos is None:
                return
            elif Terminal_Infos.pos == len(Terminal_Infos.input_list)-1:
                return
            else:
                pos = Terminal_Infos.pos
            pos += 1
            entry_cmd_text.set('')
            self.command_input.insert('end', Terminal_Infos.input_list[pos])
            Terminal_Infos.pos = pos#记录位置
            #self.command_input.xview_moveto(1)
        except Exception:
            pass
        finally:
            self.command_input.focus_set()

    #运行输入的内容调用的函数
    def run_command(self,command,terminal,commandinput):
        if Terminal_Infos.vuln is None:
            Terminal_Infos.vuln = importlib.import_module('.%s'%self.appName, package='EXP')
        
        if command == '':
            self.contiune_command()
            return
        errortext=f'错误指令"{command.strip()}".'

        command=str(command)#这玩意是应付编辑器不知道command是什么类型的
        Terminal_Infos.input_list.append(command)#增加输入了什么命令
        terminal.config(state='n')#解锁terminal(Text)

        terminal.delete('end')#删除输入控件
        commandinput.delete(0,'end')#删除控件里输入的文本

        self.thread_it(self.exeCMD,**{
            'url' : self.target,
            'cookie' : '',
            'cmd':Terminal_Infos.input_list[-1],
            'pocname' : self.pocname,
            'vuln' : 'True',
            'timeout' : int(Ent_B_Top_timeout.get()),
            'retry_time' : int(Ent_B_Top_retry_time.get()),
            'retry_interval' : int(Ent_B_Top_retry_interval.get()),
            'pool_num' : int(Ent_B_Top_thread_pool.get()),
            }
        )

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动

    #漏洞利用界面执行命令函数
    def exeCMD(self, **kwargs):
        from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
        self.TerminalText.config(state='n')#解锁terminal(Text)
        self.TerminalText.insert('end', kwargs['cmd']+'\n')
        self.TerminalText.config(state='d')
        if kwargs['url'] == '' or kwargs['cmd'] == '':
            return
        #start = time.time()
        pool = ThreadPoolExecutor(kwargs['pool_num'])
        kwargs['pool'] = pool
        GlobalVar.set_value('thread_list', [])
        try:
            #print(kwargs['cmd'])
            Terminal_Infos.vuln.check(**kwargs)
            wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
        except Exception as e:
            print('出现错误: %s'%e)
        #end = time.time()
        #print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
        pool.shutdown()
        self.contiune_command()

    def contiune_command(self):
        self.TerminalText.config(state='n')#解锁terminal(Text)
        self.TerminalText.insert('end',f'\n{os.getcwd()}'+':~# ','green')
        self.TerminalText.window_create('end', window=self.command_input)
        self.command_input.focus_set()
        self.TerminalText.config(state='d')
        self.TerminalText.see('end')

    #退出时执行的函数
    def callbackClose(self):
        try:
            sys.stdout = TextRedirector(self.Text_note, "stdout", index="2")
            sys.stderr = TextRedirector(self.Text_note, "stderr", index="2")
            self.Terminal.destroy()
        except Exception:
            self.Terminal.destroy()