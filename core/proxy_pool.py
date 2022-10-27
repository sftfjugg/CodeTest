# -*- coding: utf-8 -*-
from tkinter import Toplevel,Frame,Menu,Label,ttk,Button,Scrollbar
from tkinter import HORIZONTAL,END,W
from settings import variable_dict,Proxy_web,rootPath
from Proxy.helper.proxy import Proxy as Proxy_cls
from Proxy.proxyFetcher import ProxyFetcher
from Proxy.helper.check import DoValidator
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from ClassCongregation import seconds2hms,LoadCMD,addToClipboard
import util.globalvar as GlobalVar
import threading
import subprocess
import socket
import socks
import time
import json
import os
class Proxy_pool():
    def __init__(self, gui):
        self.gui = gui
        self.Proxy = Toplevel(gui.root)
        self.Proxy.title("免费代理")
        self.Proxy.geometry('450x500+650+150')
        self.Proxy.iconbitmap('python.ico')
        self.exchange = self.Proxy.resizable(width=False, height=False)#不允许扩大
        #self.Proxy.wm_attributes('-topmost',1)
        self.Proxy_list = []
        self.columns = ("proxy", "protocol", "anonymous")

        self.frmA = Frame(self.Proxy, width=450, height=60, bg="whitesmoke")
        self.frmB = Frame(self.Proxy, width=450, height=390, bg="whitesmoke")
        self.frmC = Frame(self.Proxy, width=450, height=10, bg="whitesmoke")
        
        self.frmA.grid(row=0, column=0, padx=3, pady=3)
        self.frmB.grid(row=1, column=0, padx=1, pady=1)
        self.frmC.grid(row=2, column=0, padx=1, pady=1)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        self.frmC.grid_propagate(0)

        self.menubar = Menu(self.Proxy)

        self.menubar.add_command(label = "打开", command=lambda:LoadCMD('/Proxy'))
        self.menubar.add_command(label = "保存", command=self.save_tree)
        self.menubar.add_command(label = "清空", command=self.del_tree)
        self.menubar.add_command(label = "显示", command=self.show_proxy)
        self.menubar.add_command(label = "去重", command=self.remove_same)
        self.menubar.add_command(label = "重新载入", command=lambda :self.reload())
        self.menubar.add_command(label = "HTTP", command=lambda :self.select_tree(selPro='HTTP'))
        self.menubar.add_command(label = "HTTPS", command=lambda :self.select_tree(selPro='HTTPS'))
        #self.menubar.add_command(label="检查代理存活性", command=lambda :self.thread_it(self.checkProxy))

        self.Proxy.config(menu = self.menubar)

        self.LabA = Label(self.frmA, text='来源')#显示
        self.comboxlistA = ttk.Combobox(self.frmA,width=10,textvariable=variable_dict["Proxy_webtitle"],state='readonly') #接受输入控件
        #self.comboxlistA["values"]=("米扑代理","66代理","pzzqz","神鸡代理","快代理","极速代理","云代理","小幻代理","免费代理库","89免费代理","西拉代理")
        self.comboxlistA["values"]=(
            "米扑代理",
            "快代理",
            "云代理",
            "小幻代理",
            "免费代理库",
            "89免费代理",
            "西拉代理",
            "proxy-list",
            "proxylistplus",
            "FOFA",
            "Hunter",
            "360Quake",
            "ZoomEye"
            )
        self.LabA1 = Label(self.frmA, text='页数')#显示
        self.comboxlistA1 = ttk.Combobox(self.frmA,width=3,textvariable=variable_dict["Proxy_page"],state='readonly') #接受输入控件
        self.comboxlistA1["values"]=("1","2","3","4","5","6","7","8","9","10")

        #self.comboxlistA2 = ttk.Combobox(self.frmA,width=3,textvariable=variable_dict["Proxy_page"],state='readonly') #接受输入控件
        #self.comboxlistA2["values"]=("1","2","3","4","5","6","7","8","9","10")

        #获取代理功能按钮
        self.buttonA = Button(self.frmA, text="获取", width=19, height=2, command=lambda :self.thread_it(self.get_proxy))

        self.VScroll1 = Scrollbar(self.frmB, orient='vertical')
        self.tree = ttk.Treeview(self.frmB, height=18, columns=self.columns, show="headings",yscrollcommand=self.VScroll1.set)
        self.VScroll1['command'] = self.tree.yview
    
        #self.tree.bind("<ButtonRelease-1>", lambda x: self.rightKey(x, self.gui.menubar_1))#绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, self.gui.menubar_1))#绑定右键鼠标事件
        # 绑定左键双击事件
        self.tree.bind("<Double-1>", lambda x: self.set_proxy())
        self.tree.heading("proxy", text="IP地址", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'proxy', False))
        self.tree.heading("protocol", text="类型", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'protocol', False))
        self.tree.heading("anonymous", text="匿名度", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'anonymous', False))
        # 定义各列列宽及对齐方式
        self.tree.column("proxy", width=220, anchor="w")
        self.tree.column("protocol", width=100, anchor="center")
        self.tree.column("anonymous", width=100, anchor="center")


        self.p1 = ttk.Progressbar(self.frmC, length=445, mode="determinate", maximum=400, orient=HORIZONTAL)
        self.p1.grid(row=0,column=0,sticky=W)
        #布局方式
        self.LabA.grid(row=0, column=0,padx=2, pady=2)
        self.comboxlistA.grid(row=0, column=1,padx=2, pady=2)
        self.LabA1.grid(row=0, column=2,padx=2, pady=2)
        self.comboxlistA1.grid(row=0, column=3,padx=2, pady=2)
        self.buttonA.grid(row=0, column=4,padx=3, pady=3)

        self.tree.grid(row=0,column=0,padx=1, pady=1)#grid方案
        self.VScroll1.grid(row=0,column=1,padx=1, pady=1,sticky='ns')
        #关联回调函数
        self.Proxy.protocol("WM_DELETE_WINDOW", self.close)
        #初始化
        self.init_proxylist()

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
    #去重
    def remove_same(self):
        temp_list = []
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[0]
            if item_text in temp_list:
                self.tree.delete(item)
            else:
                temp_list.append(item_text)
    #筛选
    def select_tree(self, selPro=''):
        selPro = True if selPro == 'HTTPS' else False
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[1]
            if selPro and 'HTTPS' in item_text:
                pass
            elif selPro and 'HTTPS' not in item_text:
                #删除HTTP节点
                self.tree.delete(item)
            elif 'HTTPS' == item_text:
                #删除HTTPS节点
                self.tree.delete(item)

    #导入1
    def init_proxylist(self):
        with open('./Proxy/ips.json', mode='r', encoding='utf-8') as f:
            for line in f.readlines():
                try:
                    _dict = json.loads(line.strip('\n'))
                    self.Proxy_list.append(_dict.get("proxy", ""))
                    self.tree.insert("","end",values=(
                                _dict.get("proxy", ""),
                                _dict.get("protocol", ""),
                                _dict.get("anonymous", "")
                                )
                            )
                except Exception:
                    continue

    #获取代理1
    def get_proxy(self):
        try:
            p = ProxyFetcher()
            # 反射调用函数
            result = getattr(p, Proxy_web[variable_dict["Proxy_webtitle"].get()])(variable_dict["Proxy_page"].get())

            for i in [_.split("|") for _ in result]:
                self.tree.insert("","end",values=(i[0], i[1], i[2]))
                self.Proxy_list.append(i[0])
        except Exception as e:
            print(e)
    #输出代理1
    def show_proxy(self):
        temp = self.get_tree()
        for i in temp:
            print(i.get("proxy", ""))

    #清空所有
    def del_tree(self):
        x = self.tree.get_children()
        for item in x:
            self.tree.delete(item)

    #重载
    def reload(self):
        self.del_select()
        self.init_proxylist()

    #删除选中的行1
    def del_select(self):
        for selected_item in self.tree.selection():
            self.tree.delete(selected_item)

    # 复制选中行到剪切板中
    def copy_select(self, event):
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                # 列
                column = self.tree.identify_column(event.x)
                cn = int(str(column).replace('#',''))
                target = item_text[cn-1]
            addToClipboard(target)
        except Exception:
            pass

    #保存当前数据1
    def save_tree(self):
        with open('./Proxy/ips.json', mode='w', encoding='utf-8') as f:
            f.writelines([json.dumps(i)+'\n' for i in self.get_tree()])
            f.close()

    #获取当前数据1
    def get_tree(self):        
        temp_list = []
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")
            str_to_dict = '{"proxy":"%s", "protocol":"%s", "anonymous":"%s"}'%(item_text[0], item_text[1], item_text[2])
            temp_list.append(json.loads(str_to_dict))
        return temp_list

    #排序函数
    def treeview_sort_column(self, tv, col, reverse):#Treeview、列名、排列方式
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        #print(tv.get_children(''))
        l.sort(reverse=reverse)#排序方式
        # rearrange items in sorted positions
        for index, (val, k) in enumerate(l):#根据排序后索引移动
            tv.move(k, '', index)
            #print(k)
        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))#重写标题，使之成为再点倒序的标题


    #检查代理存活性
    def checkProxy(self, anonymous):
        temp_list = self.get_tree()
        self.Proxy_list.clear()
        result_list = []
        self.p1["value"] = 0
        try:
            start = time.time()
            flag = round(400/len(temp_list), 2)#每执行一个任务增长的长度
            index = [Proxy_cls(**kwargs) for kwargs in temp_list]
            # 30线程
            executor = ThreadPoolExecutor(max_workers = 30)
            for data in executor.map(DoValidator.http_or_https_or_socks5_or_socks4, index, repeat(anonymous)):
                result_list.append(data)#汇聚结果
                self.p1["value"] = self.p1["value"] + flag#进度条
                self.gui.root.update()
    
            self.del_tree()
            for proxy in index:
                if proxy.last_status is not None:
                    self.Proxy_list.append(proxy.proxy)
                    self.tree.insert("","end",values=(proxy.proxy, proxy.protocol, proxy.anonymous))
            end = time.time()
            executor.shutdown()
            print('[*]检查完成!\n[*]当前存活IP: %s 个\n[*]共花费时间: %s 秒'%(len(self.Proxy_list),seconds2hms(end - start)))
            #messagebox.showinfo(title='提示', message='检查完成!\n[*]当前存活IP: %s 个\n[*]共花费时间: %s 秒'%(len(self.Proxy_list),seconds2hms(end - start)))
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*]检查完成!\n[*]当前存活IP: %s 个\n[*]共花费时间: %s 秒"%(len(self.Proxy_list),seconds2hms(end - start)))

        except Exception as e:
            print('[-]检查代理存活性错误: %s'%e)
            #messagebox.showinfo(title='错误', message='错误: %s'%e)
            self.p1["value"] = 400
            self.gui.root.update()

    ##右键鼠标事件
    def treeviewClick(self, event, menubar):
            menubar.delete(0,END)
            menubar.add_command(label='复制', command=lambda:self.copy_select(event))
            menubar.add_command(label='删除', command=lambda:self.del_select)
            menubar.add_command(label='设置为当前代理', command=self.set_proxy)
            menubar.add_command(label='开启HTTP代理池mubeng port:8089', command=self.open_proxy)
            menubar.add_command(label='开启SOCKS代理池rotateproxy port:8899', command=self.open_rotateproxy)
            menubar.add_command(label='根据协议类型检测代理存活性', command=lambda :self.thread_it(self.checkProxy, anonymous=False))
            #menubar.add_command(label='检测高匿代理存活性', command=lambda :self.thread_it(self.checkProxy, anonymous=True))
            #menubar.add_command(label='检测HTTP代理存活', command=lambda:self.set_proxy(ip,port,pro))
            #menubar.add_command(label='检测HTTPS代理存活', command=lambda:self.set_proxy(ip,port,pro))
            #menubar.add_command(label='开启全局代理连接池', command=lambda :self.thread_it(self.start_proxy))
            menubar.post(event.x_root,event.y_root)

    #设置代理
    def set_proxy(self):
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                proxy = item_text[0]
                protocol = item_text[1]
            ip, port = proxy.split(':')
            #代理初始化清空
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            #自定义值
            variable_dict["Proxy_CheckVar1"].set(1)
            variable_dict["Proxy_CheckVar2"].set(0)
            variable_dict["Proxy_addr"].set(ip)
            variable_dict["Proxy_port"].set(port)
            # HTTP/HTTPS 代理
            if protocol == 'HTTP' or protocol == 'HTTPS':
                variable_dict["PROXY_TYPE"].set('HTTP/HTTPS')
                os.environ['HTTP_PROXY'] = ip+':'+port
                os.environ['HTTPS_PROXY'] = ip+':'+port
            # SOCKS代理
            else:
                if protocol == "SOCKS4":
                    proxy_type = socks.SOCKS4
                elif protocol == "SOCKS5":
                    proxy_type = socks.SOCKS5
                variable_dict["PROXY_TYPE"].set(protocol)
                socks.set_default_proxy(proxy_type, ip, int(port))
                socket.socket = socks.socksocket
            print('[*]设置代理成功\n[*]当前代理协议: %s\n[*]当前代理的IP: %s:%s'%(protocol,ip,port))
        except Exception as e:
            print('[-]设置代理错误: %s'%e)

    def open_proxy(self):
        # 获取代理
        temp_list = []
        item_list = self.tree.get_children() if len(self.tree.selection()) == 0 else self.tree.selection()
        for item in item_list:
            item_text = self.tree.item(item,"values")
            if item_text[1] not in ['SOCKS5','SOCKS4','HTTPS','HTTP']:
                str_to_dict = '%s://%s'%('HTTP', item_text[0])
            else:
                str_to_dict = '%s://%s'%(item_text[1], item_text[0])
            temp_list.append(str_to_dict.lower()+'\n')
        # 保存代理
        with open('./Proxy/proxies.txt', mode='w', encoding='utf-8') as f:        
            f.writelines(temp_list)
            f.close()
        try:
            m = "%s\Proxy\mubeng -a 127.0.0.1:8089 -f %s\Proxy\proxies.txt --check --rotate 1 --timeout 5s --method random"%(rootPath, rootPath)
            command = 'cmd.exe /k ' + m
            subprocess.Popen(command, shell=False, creationflags=subprocess.CREATE_NEW_CONSOLE)

            # 代理初始化清空
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            # 自定义值
            variable_dict["Proxy_CheckVar1"].set(1)
            variable_dict["Proxy_CheckVar2"].set(0)
            variable_dict["Proxy_addr"].set('127.0.0.1')
            variable_dict["Proxy_port"].set('8089')
            variable_dict["PROXY_TYPE"].set('HTTP/HTTPS')
            # 设置代理
            os.environ['HTTP_PROXY'] = '127.0.0.1:8089'
            os.environ['HTTPS_PROXY'] = '127.0.0.1:8089'
            print('[*]设置代理成功\n[*]当前代理协议: %s\n[*]当前代理的IP: %s:%s'%('HTTP/HTTPS','127.0.0.1','8089'))
        except Exception as e:
            print(e)

    def open_rotateproxy(self):
        try:
            m = "%s\Proxy\\rotateproxy -email %s -token %s -page %s -l %s -region %s"%(
                rootPath,
                GlobalVar.get_value('FOFA_EMAIL'),
                GlobalVar.get_value('FOFA_KEY'),
                '5',
                ':8899',
                '2',
            )
            command = 'cmd.exe /k ' + m
            subprocess.Popen(command, shell=False, creationflags=subprocess.CREATE_NEW_CONSOLE)

            # 代理初始化清空
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            # 自定义值
            variable_dict["Proxy_CheckVar1"].set(1)
            variable_dict["Proxy_CheckVar2"].set(0)
            variable_dict["Proxy_addr"].set('127.0.0.1')
            variable_dict["Proxy_port"].set('8899')
            variable_dict["PROXY_TYPE"].set('SOCKS5')
            # 设置代理
            socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', 8899)
            # 应用
            socket.socket = socks.socksocket
            print('[*]设置代理成功\n[*]当前代理协议: %s\n[*]当前代理的IP: %s:%s'%('SOCKS5','127.0.0.1','8899'))
        except Exception as e:
            print(e)

    #多线程执行函数
    def thread_it(self, func, **kwargs):
        self.t = threading.Thread(target=func, kwargs=kwargs, name='执行函数子线程')
        self.t.setDaemon(True)   # 守护
        self.t.start()           # 启动