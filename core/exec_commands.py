from settings import Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_thread_pool,Proxy_CheckVar1
from tkinter import Button,Frame,Toplevel,scrolledtext,messagebox
from tkinter import TOP,BOTTOM,BOTH
from urllib.parse import quote
from settings import rootPath
import util.globalvar as GlobalVar
import importlib
import threading

#批量命令执行界面
class Exec_Commands():
    scan_list = []
    vulns = []
    kwargs = []
    items = []
    def __init__(self, root, tree, **kwargs):
        self.cmdscreen = Toplevel(root)
        #新建Text控件
        self.title = self.cmdscreen.title('批量执行命令')#设置title
        self.size = self.cmdscreen.geometry('600x500+600+150')#设置窗体大小，960x650是窗体大小，400+50是初始位置
        self.cmdscreen.iconbitmap(rootPath+'/python.ico')
        
        self.tree = tree
        self.flag = kwargs.get('flag', '')
        
        self.frmtop = Frame(self.cmdscreen, width=600,height=400, bg='red')
        self.frmbottom = Frame(self.cmdscreen, width=600, height=100,bg='green')
        
        self.frmtop.grid_propagate(0)
        self.frmbottom.grid_propagate(0)
        
        self.frmtop.pack(side=TOP, fill=BOTH, expand=1)
        self.frmbottom.pack(side=BOTTOM, fill=BOTH, expand=1)
        
        self.TerminalText = scrolledtext.ScrolledText(self.frmtop, width=70, height=20, font=('consolas',10))
        self.TerminalText.pack(fill=BOTH, expand=1)
        
        self.button = Button(self.frmbottom, text='执   行', command=lambda:self.fillenv())
        self.button.pack(fill=BOTH, expand=1)
        #关联回调函数
        self.cmdscreen.protocol("WM_DELETE_WINDOW", self.close)
    def hide(self):
        """
        隐藏界面
        """
        self.cmdscreen.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.cmdscreen.update()
        self.cmdscreen.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()
    def fillenv(self):
        try:
            cmd = self.TerminalText.get('0.0','end').strip('\n')        
            if cmd == '':
                self.cmdscreen.destroy()
                messagebox.showinfo(title='结果', message='请先输入命令!')
                return
            #探测所有
            if self.flag == 'ALL':
                x = self.tree.get_children()
            #探测所选
            else:
                x = self.tree.selection()
            if len(x) == 0:
                self.cmdscreen.destroy()
                messagebox.showinfo(title='结果', message='未选中目标!')
                return
            if Proxy_CheckVar1.get() == 0 and len(x) > 10:
                if messagebox.askokcancel('提示','程序检测到未挂代理进行扫描,请确认是否继续?') == False:
                    print("[-]扫描已取消!")
                    return
            #验证前清空列表
            Exec_Commands.vulns.clear()
            Exec_Commands.kwargs.clear()
            Exec_Commands.items.clear()
            for item in x:
                item_text = self.tree.item(item,"values")
                target = item_text[1]
                appName = item_text[2]
                pocname = item_text[3]
                try:
                    Exec_Commands.vulns.append(importlib.import_module('.%s'%appName, package='EXP'))
                    Exec_Commands.kwargs.append({
                        'url' : target,
                        'cookie' : '',
                        'cmd' : quote(cmd),
                        'pocname' : pocname,
                        'vuln' : 'True',
                        'timeout' : int(Ent_B_Top_timeout.get()),
                        'retry_time' : int(Ent_B_Top_retry_time.get()),
                        'retry_interval' : int(Ent_B_Top_retry_interval.get()),
                    })
                    Exec_Commands.items.append(item)
                except Exception:
                    continue
            self.thread_it(self.exeCMD,**{
                'pool_num' : int(Ent_B_Top_thread_pool.get())
            })
        except Exception:
            messagebox.showinfo(title='错误', message='未选中目标!')

    def exeCMD(self, **kwargs):
        from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
        if len(Exec_Commands.vulns) == 0:
            messagebox.showinfo(title='提示', message='还未选择模块')
            return
        #初始化全局子线程列表
        pool = ThreadPoolExecutor(kwargs['pool_num'])
        GlobalVar.set_value('thread_list', [])
        for index in range(len(Exec_Commands.vulns)):
            Exec_Commands.kwargs[index]['pool'] = pool
            Exec_Commands.vulns[index].check(**Exec_Commands.kwargs[index])
        #依次等待线程执行完毕
        wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
        #关闭线程池
        pool.shutdown()
        messagebox.showinfo(title='结果', message='执行完毕!')
        
    def thread_it(self, func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动