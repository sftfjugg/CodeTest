from tkinter import Toplevel,Frame,Checkbutton,Label,ttk,Entry,Button
from tkinter import W
from settings import variable_dict
import socket
import socks
import os

class TopProxy():
    def __init__(self, gui):
        global variable_dict

        self.Proxy = Toplevel(gui.root)
        self.Proxy.title("代理服务器设置")
        self.Proxy.geometry('350x300+650+150')
        self.Proxy.iconbitmap('python.ico')
        self.exchange = self.Proxy.resizable(width=False, height=False)#不允许扩大

        self.frmA = Frame(self.Proxy, width=350, height=50, bg="whitesmoke")
        self.frmB = Frame(self.Proxy, width=350, height=90, bg="whitesmoke")
        self.frmC = Frame(self.Proxy, width=350, height=130, bg="whitesmoke")
        self.frmA.grid(row=0, column=0, padx=10, pady=10)
        self.frmB.grid(row=1, column=0, padx=2, pady=2)
        self.frmC.grid(row=2, column=0, padx=2, pady=2)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        self.frmC.grid_propagate(0)

        self.button1 = Checkbutton(self.frmA,text="启用",command=lambda:self.Yes(),variable=variable_dict["Proxy_CheckVar1"])
        self.button2 = Checkbutton(self.frmA,text="禁用",command=lambda:self.No(),variable=variable_dict["Proxy_CheckVar2"])
        
        self.button1.grid(row=0, column=0)
        self.button2.grid(row=0, column=1)

        self.LabA = Label(self.frmB, text='类   型')#显示
        #接受输入控件
        self.comboxlistA = ttk.Combobox(self.frmB,width=12,textvariable=variable_dict["PROXY_TYPE"],state='readonly')
        #绑定参数
        self.comboxlistA.bind("<<ComboboxSelected>>", self.bind_combobox_3)
        self.comboxlistA["values"]=("HTTP/HTTPS","SOCKS5","SOCKS4")
        # self.comboxlistA["values"]=("HTTP","HTTPS","HTTP/HTTPS","SOCKS5","SOCKS4")
        #self.comboxlistA.current(0)

        self.LabB = Label(self.frmB, text='IP地址')#显示
        self.EntB = Entry(self.frmB, width=25,textvariable=variable_dict["Proxy_addr"]) #接受输入控件

        self.LabC = Label(self.frmB, text='端   口')#显示
        self.EntC = Entry(self.frmB, width=25,textvariable=variable_dict["Proxy_port"]) #接受输入控件

        #self.LabD = Label(self.frmB, text='用户名:')#显示
        #self.EntD = Entry(self.frmB, width='30') #接受输入控件

        #self.LabE = Label(self.frmB, text='密码:')#显示
        #self.EntE = Entry(self.frmB, width='30') #接受输入控件

        self.LabA.grid(row=0, column=0,padx=2, pady=2,sticky=W)
        self.comboxlistA.grid(row=0, column=1,padx=2, pady=2,sticky=W)

        self.LabB.grid(row=1, column=0,padx=2, pady=2,sticky=W)
        self.EntB.grid(row=1, column=1,padx=2, pady=2)

        self.LabC.grid(row=2, column=0,padx=2, pady=2,sticky=W)
        self.EntC.grid(row=2, column=1,padx=2, pady=2)

        self.buttonD = Button(self.frmC,text='还原',width=20,command=self.old)
        self.buttonE = Button(self.frmC,text='输出代理',width=20,command=self.show_proxy)
        self.buttonD.grid(row=0,column=0,padx=2,pady=2)
        self.buttonE.grid(row=1,column=0,padx=2,pady=2)
        #关联回调函数
        self.Proxy.protocol("WM_DELETE_WINDOW", self.close)

    def hide(self):
        """
        隐藏界面
        """
        self.Proxy.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.Proxy.update()
        self.Proxy.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()
        
    def Yes(self):
        variable_dict["Proxy_CheckVar2"].set(0)
        if variable_dict["Proxy_CheckVar1"].get() == 1:

            proxy_str = variable_dict["PROXY_TYPE"].get()
            ip = self.EntB.get() if self.EntB.get() else None
            port = self.EntC.get() if self.EntC.get() else None
            #username = self.EntD.get() if self.EntD.get() else None
            #passwd = self.EntE.get() if self.EntE.get() else None

            if proxy_str == "HTTP":
                os.environ['HTTP_PROXY'] = ip+':'+port
            elif proxy_str == "HTTPS":
                os.environ['HTTPS_PROXY'] = ip+':'+port
            elif proxy_str == "HTTP/HTTPS":
                os.environ['HTTP_PROXY'] = ip+':'+port
                os.environ['HTTPS_PROXY'] = ip+':'+port
            else:
                if proxy_str == "SOCKS4":
                    proxy_type = socks.SOCKS4
                elif proxy_str == "SOCKS5":
                    proxy_type = socks.SOCKS5
                socks.set_default_proxy(proxy_type, ip, int(port))
                # socks.socksocket.settimeout(10)
                socket.socket = socks.socksocket
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*] 设置代理成功")
            print('[*]设置代理成功')
        else:
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*] 取消代理")
            print('[*]取消代理')

        
    def No(self):
        variable_dict["Proxy_CheckVar1"].set(0)
        if variable_dict["Proxy_CheckVar2"].get() == 1:
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            print('[*]禁用代理')
            
    def old(self):
        variable_dict["Proxy_CheckVar1"].set(0)
        variable_dict["Proxy_CheckVar2"].set(0)
        variable_dict["PROXY_TYPE"].set('HTTP/HTTPS')
        variable_dict["Proxy_addr"].set('127.0.0.1')
        variable_dict["Proxy_port"].set('8080')
        socks.set_default_proxy(None)
        socket.socket = socks.socksocket
        os.environ['HTTP_PROXY'] = ''
        os.environ['HTTPS_PROXY'] = ''
        
    def show_proxy(self):
        print('[*]HTTP_PROXY: '+os.environ['HTTP_PROXY'])
        print('[*]HTTPS_PROXY: '+os.environ['HTTPS_PROXY'])
        
    def bind_combobox_3(self, *args):
        x = variable_dict["PROXY_TYPE"].get()
        if x == 'SOCKS5' or x == 'SOCKS4':
            variable_dict["Proxy_port"].set('1080')
        else:
            variable_dict["Proxy_port"].set('8080')