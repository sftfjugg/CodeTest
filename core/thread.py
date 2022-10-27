# -*- coding: utf-8 -*-
from tkinter import Button, Frame,Menu,messagebox,PanedWindow,Label,Entry,Scrollbar,ttk
from tkinter import X,END,INSERT,TOP,BOTH,RIGHT,LEFT,NONE,Y,HORIZONTAL,VERTICAL,N,S,E,W,YES,NO
from settings import Ent_Thread_ip,Ent_Thread_domain
from ClassCongregation import addToClipboard,FrameProgress
from util.fun import isIP
import threading
import time

errorFlag = ['None','Error','CDN','', {}, [], None]

class Thread():
    def __init__(self, gui):
        self.frmthread = gui.frmthread
        self.root = gui.root
        # 创建一个菜单
        self.menubar = Menu(self.root, tearoff=False)
        self.dict = {}

    def CreateFrm(self):
        # 创建顶级菜单
        self.frm = Frame(self.frmthread, width=1160, height=700, bg='whitesmoke')
        self.frm.pack(expand=1, fill=BOTH)
        # 分三份
        self.frame_1 = Frame(self.frm, width=1160, height=40, bg='whitesmoke')
        self.frame_2 = Frame(self.frm, width=1160, height=620, bg='whitesmoke')
        self.frame_3 = Frame(self.frm, width=1160, height=10, bg='whitesmoke')
        # 布局定位
        self.frame_1.pack(side=TOP, expand=0, fill=X)
        self.frame_2.pack(side=TOP, expand=1, fill=BOTH)
        self.frame_3.pack(side=TOP, expand=0, fill=X)
        # 构建一个水平方向的PanedWindow控件，grid布局时sticky属性设置为四面填充
        self.paned_window = PanedWindow(self.frame_2, orient=HORIZONTAL, bg='whitesmoke')
        self.paned_window.pack(expand=1, fill=BOTH)

        #构建管理左侧控件的Frame对象
        self.tree_area = Frame(self.paned_window, width=300, height=620, bg='whitesmoke')
        self.tree_area.grid_rowconfigure(0, weight=1)
        self.tree_area.grid_columnconfigure(0, weight=1)
        self.paned_window.add(self.tree_area)
        
        # 设定右边的滚动
        self.ybar = Scrollbar(self.tree_area, orient='vertical')
        # 构建Treeview控件。将show属性指定为'tree'可以消除顶部的标题行
        self.tree_view = ttk.Treeview(self.tree_area, height=30, show='tree', selectmode='browse')
        # 绑定按钮事件
        self.tree_view.bind('<<TreeviewOpen>>', self.open_node)
        self.tree_view.bind("<Button-3>", lambda x: self.treeviewClick2(x, self.menubar, self.tree_view))
        # 设置颜色
        self.tree_view.tag_configure('tag_beian', background='green')
        self.tree_view.grid(row=0, column=0, sticky='nsew')
        # 添加水平和垂直滚动条
        self.scroll_ty = Scrollbar(self.tree_area, orient=VERTICAL, command=self.tree_view.yview)
        self.scroll_ty.grid(row=0, column=1, sticky=N+S)
        self.tree_view['yscrollcommand']=self.scroll_ty.set

        #构建右侧显示区域
        self.detail_area = Frame(self.paned_window, width=860, height=620, bg='whitesmoke')
        self.detail_area.grid_rowconfigure(0, weight=1)
        self.detail_area.grid_columnconfigure(0, weight=1)
        self.paned_window.add(self.detail_area)
        
        self.list_view = ttk.Treeview(self.detail_area, height=30, show="headings", columns=('type','value'))
        self.list_view.bind("<Button-3>", lambda x: self.treeviewClick(x, self.menubar, self.list_view))

        self.list_view.column("type", width=150, minwidth=150, stretch=YES, anchor="center")
        self.list_view.column("value", width=750, minwidth=100, stretch=YES, anchor="center")

        self.list_view.heading("type", text="字段", anchor="center")
        self.list_view.heading("value", text="值", anchor="center")
        
        self.list_view.grid(row=0, column=0, sticky='nsew')
        
        #构建Scrollbar和Sizegrip控件
        self.scroll_fy = Scrollbar(self.detail_area, orient=VERTICAL, command=self.list_view.yview)
        self.scroll_fy.grid(row=0, column=1, sticky=N+S)
        self.list_view['yscrollcommand']=self.scroll_fy.set
        
    def Createframe_1(self):
        # 标签
        self.frame_1_label_1 = Label(self.frame_1, text="IP")
        # 接受输入控件
        self.frame_1_Ent_1 = Entry(self.frame_1, width='1', highlightcolor='red', highlightthickness=1, textvariable=Ent_Thread_ip, font=("consolas",10))
        # 标签
        self.frame_1_label_2 = Label(self.frame_1, text="Domain")
        # 接受输入控件
        self.frame_1_Ent_2 = Entry(self.frame_1, width='65', highlightcolor='red', highlightthickness=1, textvariable=Ent_Thread_domain, font=("consolas",10))
        # 按钮
        import util.globalvar as GlobalVar
        self.myurls = GlobalVar.get_value('myurls')
        self.frame_1_Button_1 = Button(self.frame_1, text='......', width=6, command=lambda :self.myurls.show())
        self.frame_1_Button_2 = Button(self.frame_1, text='查 找', width=6, command=lambda v=0:self.thread_it(self.find))
        # pack布局
        self.frame_1_label_1.pack(side=LEFT, expand=0, fill=NONE)
        self.frame_1_Ent_1.pack(side=LEFT, expand=1, fill=X)
        self.frame_1_label_2.pack(side=LEFT, expand=0, fill=NONE)
        self.frame_1_Ent_2.pack(side=LEFT, expand=1, fill=X)
        self.frame_1_Button_1.pack(side=LEFT, expand=0, fill=NONE)
        self.frame_1_Button_2.pack(side=LEFT, expand=0, fill=NONE)
        
    def Createframe_2(self):
        self.frame_progress = FrameProgress(self.frame_3, height=10, maximum=1000)
        self.frame_progress.pack(expand=0, fill=X)
        
    def find(self):
        ip = Ent_Thread_ip.get().strip('\n').strip(' ')
        domain = Ent_Thread_domain.get().strip('\n').strip(' ')
        # 去除上次查找的错误值
        if ip == 'Error':
            ip = ''
        if domain == 'Error':
            domain = ''

        from ThreatInfo.check import DoCollect
        from ThreatInfo.threadinfo import Threadinfo

        if ip or domain:
            # 进度条初始化为100,代表程序已开始运行
            self.frame_progress.pBar["value"] = 100
            # 清空当前数据
            self.del_tree()
            flag = round(900/4, 2)#每执行一个任务增长的长度
            one = Threadinfo(ip=ip, domain=domain)
            try:
                # 基础条件转换,设置值
                DoCollect.domain2ipCollect(one)
                DoCollect.ip2domainCollect(one)
            except Exception:
                pass
            Ent_Thread_ip.set(one.ip)
            Ent_Thread_domain.set(one.domain)
            # #基础属性节点
            # ip_node = self.tree_view.insert(root_node, 'end', text='ip', open=False)
            # domain_node = self.tree_view.insert(root_node, 'end', text='domain', open=False)
            # ipWhois_node = self.tree_view.insert(root_node, 'end', text='ipWhois', open=False)
            # domainWhois_node = self.tree_view.insert(root_node, 'end', text='domainWhois', open=False)
            # beianWhois_node = self.tree_view.insert(root_node, 'end', text='beianWhois', open=False)
            # aiqicha_node = self.tree_view.insert(root_node, 'end', text='aiqicha', open=False)
            #进度条增长
            self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
            try:
                # ipWhois
                DoCollect.ipWhoisCollect(one)
                if one.ipWhois not in errorFlag:
                    for item in one.ipWhois.items():
                        self.list_view.insert("","end",values=(item))
            except Exception:
                pass
            finally:
                #进度条增长
                self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
            try:
                # domainWhois
                DoCollect.domainWhoisCollect(one)
                if one.domainWhois not in errorFlag:
                    for item in one.domainWhois.items():
                        self.list_view.insert("","end",values=(item))
            except Exception:
                pass
            finally:
                #进度条增长
                self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
            try:
                # beianWhois
                DoCollect.beianWhoisCollect(one)
                if one.beianWhois not in errorFlag:
                    for item in one.beianWhois.items():
                        self.list_view.insert("","end",values=(item))
            except Exception:
                pass
            finally:
                #进度条增长
                self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
                
            try:
            # threatbook
                DoCollect.threatbookCollect(one)
                if one.threatbook not in errorFlag:
                    for item in one.threatbook.items():
                        self.list_view.insert("","end",values=(item))
            except Exception:
                pass
            finally:
                #进度条增长
                self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag

            # try:
            # # aiqicha
            #     DoCollect.aiqichaCollect(one)
            #     self.list_view.insert("","end",values=(item))
            # except Exception:
            #     pass
            # finally:
            #     #进度条增长
            #     self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
            #save
            #插入item
            if ip:            
                now_item = self.tree_view.insert('', 'end', text=ip, open=False)
                self.dict[ip] = one.to_dict
            else:
                now_item = self.tree_view.insert('', 'end', text=domain, open=False)
                self.dict[domain] = one.to_dict
            #标记颜色
            if one.beianWhois not in errorFlag:
                self.tree_view.item(now_item, tags='tag_beian')

            # print(one.json_beautify)
        #进入多目标测试功能
        elif self.myurls.TexA.get('0.0','end').strip('\n'):
            #去空处置
            target_list = [i for i in self.myurls.TexA.get('0.0','end').split("\n") if i!='']
            target_len = len(target_list)
            # 进度条初始化为100,代表程序已开始运行
            self.frame_progress.pBar["value"] = 100
            flag = round(700/target_len, 2)#每执行一个任务增长的长度
            for target in target_list:
                #构造初值
                if isIP(target):
                    one = Threadinfo(ip=target)
                else:
                    one = Threadinfo(domain=target)
                try:
                    # 基础条件转换,设置值
                    DoCollect.domain2ipCollect(one)
                    DoCollect.ip2domainCollect(one)
                except Exception:
                    pass
                try:
                    # ipWhois
                    DoCollect.ipWhoisCollect(one)
                except Exception:
                    pass
                try:
                    # domainWhois
                    DoCollect.domainWhoisCollect(one)
                except Exception:
                    pass
                try:
                    # beianWhois
                    DoCollect.beianWhoisCollect(one)
                except Exception:
                    pass
                try:
                    # threatbook
                    DoCollect.threatbookCollect(one)
                except Exception:
                    pass
                # try:
                #     # aiqicha
                #     DoCollect.aiqichaCollect(one)
                # except Exception:
                #     pass
                now_item = self.tree_view.insert('', 'end', text=target, open=False)
                # 备案不为空则,标记绿色
                if one.beianWhois not in ['None','Error','',{},[],None]:
                    self.tree_view.item(now_item, tags='tag_beian')
                self.dict[target] = one.to_dict
                self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
                time.sleep(0.5)
            messagebox.showinfo('提示','查询完成!')

    #清空所有
    def del_tree(self):
        tree_list = [self.list_view]
        for tree in tree_list:
            x = tree.get_children()
            for item in x:
                tree.delete(item)
                
    #清空所有
    def del_tree2(self):
        tree_list = [self.tree_view]
        for tree in tree_list:
            x = tree.get_children()
            for item in x:
                tree.delete(item)
        #清空字典
        self.dict.clear()
        #右侧表格
        self.del_tree()
    
    #导出到桌面
    # def saveToExcel(self):
    #     #print(self.dict)
    #     try:
    #         from openpyxl import Workbook
    #         import os
    #         timestr = time.strftime("%Y%m%d_%H%M%S")  # 获取当前时间
    #         ExcelFile = Workbook()
    #         ExcelFileWs = ExcelFile.active
    #         ExcelFileWs.append(['序号','地址', '组件名称', '漏洞名称', '检测状态', '检测时间'])
    #         index = 1
    #         for value in self.dict.values():
                
            
    #         for item in self.tree.get_children():
    #             item_text = self.tree.item(item,"values")
    #             ExcelFileWs.append([index, item_text[1], item_text[2], item_text[3], item_text[4], item_text[5]])
    #             index += 1
    #         ExcelFile.save(os.path.join(os.path.expanduser('~'),"Desktop")+'/'+timestr+'.xlsx')
    #         messagebox.showinfo(title='结果', message='已导出数据到桌面!')
    #     except Exception as e:
    #         messagebox.showerror(title='错误', message=e)

    ##右键鼠标事件
    def treeviewClick(self, event, menubar, tree):
        menubar.delete(0,END)
        menubar.add_command(label='复制', command=lambda:self.copy_select(tree, event))
        menubar.add_command(label='清空所有', command=lambda:self.del_tree())
        menubar.post(event.x_root, event.y_root)

    ##右键鼠标事件
    def treeviewClick2(self, event, menubar, tree):
        menubar.delete(0,END)
        menubar.add_command(label='删除节点', command=lambda:self.remove_node(tree))
        menubar.add_command(label='清空所有', command=lambda:self.del_tree2())
        # menubar.add_command(label='导出桌面', command=lambda:self.saveToExcel())
        menubar.post(event.x_root, event.y_root)

    # 复制选中行到剪切板中
    def copy_select(self, tree, event):
        try:
            for item in tree.selection():
                item_text = tree.item(item,"values")
                # 列
                column = tree.identify_column(event.x)
                cn = int(str(column).replace('#',''))
                target = item_text[cn-1]
            addToClipboard(target)
        except Exception:
            pass

    def open_node(self, event):
        item = self.tree_view.focus()
        item_name = self.tree_view.item(item)['text']
        #先清除
        self.del_tree()
        #赋值
        value = self.dict[item_name]
        try:
            for item in value['ipWhois'].items():
                self.list_view.insert("","end",values=(item))
        except:
            pass
        try:
            for item in value['domainWhois'].items():
                self.list_view.insert("","end",values=(item))
        except:
            pass
        try:
            for item in value['beianWhois'].items():
                self.list_view.insert("","end",values=(item))
        except:
            pass
        try:
            for item in value['threatbook'].items():
                self.list_view.insert("","end",values=(item))
        except:
            pass
    
    def remove_node(self, tree):
        items = tree.selection()
        try:
            for item in items:
                del self.dict[tree.item(item)['text']]
        except:
            pass
        tree.delete(items)
        self.del_tree()

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)
        self.t.start()

    def start(self):
        self.CreateFrm()
        self.Createframe_1()
        self.Createframe_2()