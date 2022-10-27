# -*- coding: utf-8 -*-
from settings import exp_scripts,Ent_O_Top_source,Ent_O_Top_yufa,Ent_O_Top_page,Ent_O_Top_size,Proxy_CheckVar1,Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_thread_pool
from tkinter import Entry, Frame,Menu,Scrollbar,messagebox,ttk,Label,Button,Text
from tkinter import LEFT,RIGHT,BOTH,END,X,Y,W,HORIZONTAL,INSERT,BOTTOM,TOP,NONE
from tkinter.ttk import Style
from ClassCongregation import FrameProgress,Logger,delText,addToClipboard,seconds2hms,TextRedirector
from ThreatInfo.WebRequest import WebRequest

import util.globalvar as GlobalVar
import threading
import importlib
import time
import sys

class Zichanspace():
    columns = ("index", "host", "ip", "port", "protocol", "title", "country", "cms", "source")
    items = []
    url_list = []
    vulns = []
    kwargs = []
    def __init__(self, gui):
        self.gui = gui
        self.frmSpace = gui.frmSpace
        self.root = gui.root
        # 创建一个菜单
        self.menubar = Menu(self.root, tearoff=False)
        # self.style = Style()
        # self.style.configure('Treeview', rowheight=20)
        # self.style.map('Treeview', foreground=self.fixed_map('foreground'), background=self.fixed_map('background'))
        # # 设置选中条目的背景色和前景色
        # self.style.map('Treeview',background=[('selected','red')], foreground=[('selected','white')])
        
    def CreateFrm(self):
        self.frmtop = Frame(self.frmSpace, width=1160, height=35, bg='whitesmoke')
        self.frmmiddle = Frame(self.frmSpace, width=1160, height=630, bg='whitesmoke')
        self.frmbottom = Frame(self.frmSpace, width=1160, height=15, bg='whitesmoke')
        
        self.frmtop.pack(side=TOP, expand=0, fill=X)
        self.frmmiddle.pack(side=TOP, expand=1, fill=BOTH)
        self.frmbottom.pack(side=TOP, expand=0, fill=X)

    def CreatTop(self):
        self.label_1 = Label(self.frmtop, text="数据来源")
        self.comboxlist_1 = ttk.Combobox(self.frmtop, width='13', textvariable=Ent_O_Top_source, state='readonly')
        self.comboxlist_1["values"] = ('fofa','hunter','quake','ALL')

        self.label_2 = Label(self.frmtop, text="语法")
        self.EntA_2 = Entry(self.frmtop, width='53', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_yufa, font=("consolas",10))        

        self.label_3 = Label(self.frmtop, text="page")
        self.EntA_3 = Entry(self.frmtop, width='5', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_page, font=("consolas",10))

        self.label_4 = Label(self.frmtop, text="size")
        self.EntA_4 = Entry(self.frmtop, width='5', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_size, font=("consolas",10))

        self.label_5 = Label(self.frmtop, text='总条数')#显示
        self.text_5 = Text(self.frmtop, font=("consolas",10), width=5, height=1)
        self.text_5.configure(state="disabled")

        self.Button_1 = Button(self.frmtop, text='搜索', width=6, command=lambda:self.thread_it(self.singlesearch))
        self.Button_2 = Button(self.frmtop, text='语法', width=6, command=lambda : GlobalVar.get_value('my_yufa_pool').show())
        
        # pack布局
        self.label_1.pack(side=LEFT, expand=0, fill=NONE)
        self.comboxlist_1.pack(side=LEFT, expand=0, fill=NONE)
        self.label_2.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_2.pack(side=LEFT, expand=1, fill=X)
        self.label_3.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_3.pack(side=LEFT, expand=0, fill=NONE)
        self.label_4.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_4.pack(side=LEFT, expand=0, fill=NONE)
        self.label_5.pack(side=LEFT, expand=0, fill=NONE)
        self.text_5.pack(side=LEFT, expand=0, fill=NONE)
        self.Button_1.pack(side=LEFT, expand=0, fill=NONE)
        self.Button_2.pack(side=LEFT, expand=0, fill=NONE)

    def CreatMiddle(self):
        # 设定下边的滚动
        self.xbar = Scrollbar(self.frmmiddle, orient=HORIZONTAL)
        # 设定右边的滚动
        self.ybar = Scrollbar(self.frmmiddle, orient='vertical')
        # tree关联
        self.tree = ttk.Treeview(self.frmmiddle, height=29, columns=Zichanspace.columns, show="headings",
                                 xscrollcommand=self.xbar.set,
                                 yscrollcommand=self.ybar.set)
        
        self.xbar['command'] = self.tree.xview
        self.ybar['command'] = self.tree.yview

        self.tree.heading("index", text="index", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'index', False))
        self.tree.heading("host", text="host", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'host', False))
        self.tree.heading("ip", text="ip",  anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'ip', False))
        self.tree.heading("port", text="port", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'port', False))
        self.tree.heading("protocol", text="protocol", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'protocol', False))
        self.tree.heading("title", text="title", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'title', False))
        self.tree.heading("country", text="country", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'country', False))
        self.tree.heading("cms", text="cms", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'cms', False))
        self.tree.heading("source", text="source", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'source', False))
        
        # 设置颜色
        self.tree.tag_configure('tag_fail', background='red')
        self.tree.tag_configure('tag_success', background='green')
                
        # 定义各列列宽及对齐方式
        self.tree.column("index", width=60, anchor="center")
        self.tree.column("host", width=210, anchor="w")
        self.tree.column("ip", width=130, anchor="w")
        self.tree.column("port", width=70, anchor="center")
        self.tree.column("protocol", width=90, anchor="center")
        self.tree.column("title", width=200, anchor="w")
        self.tree.column("country", width=100, anchor="center")
        self.tree.column("cms", width=200, anchor="center")
        self.tree.column("source", width=70, anchor="center")
        
        # 绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, self.menubar))
        # 绑定左键双击事件
        self.tree.bind("<Double-1>", lambda x: self.openurl())
        """
        tree必须最后定位
        """
        # 右边的滚动在Y轴充满
        self.ybar.pack(side=RIGHT, expand=0, fill=Y)
        # 下边的滚动在X轴充满
        self.xbar.pack(side=BOTTOM, expand=0, fill=X)
        self.tree.pack(side=LEFT , expand=1, fill=BOTH)

    def CreatBottom(self):
        self.frame_progress = FrameProgress(self.frmbottom, height=10, maximum=1000)
        self.frame_progress.pack(expand=0, fill=X)
        
    #排序函数 Treeview、列名、排列方式
    def treeview_sort_column(self, tree, col, reverse):
        if col == 'index':
            l = [(int(tree.set(k, col)), k) for k in tree.get_children()]
        else:
            l = [(tree.set(k, col), k) for k in tree.get_children()]
        #排序方式
        l.sort(reverse=reverse)
        # rearrange items in sorted positions
        #根据排序后索引移动
        for index, (val, k) in enumerate(l):
            tree.move(k, '', index)
        #重写标题，使之成为再点倒序的标题
        tree.heading(col, command=lambda: self.treeview_sort_column(tree, col, not reverse))

    def singlesearch(self):
        # 进度条初始化
        self.frame_progress.pBar["value"] = 0
        # 数据来源
        source = Ent_O_Top_source.get().strip('\n')
        # 语法
        yufa = Ent_O_Top_yufa.get().strip('\n')
        # page
        page = Ent_O_Top_page.get().strip('\n')
        # size
        size = Ent_O_Top_size.get().strip('\n')
        # 请求数据
        if source == 'fofa':
            allsize, resultList = self.fofaApi(yufa, page, size)
        elif source == 'hunter':
            allsize, resultList = self.hunterApi(yufa, page, size)
        elif source == 'ALL':
            allsize1, resultList1 = self.fofaApi(yufa, page, size)
            allsize2, resultList2 = self.hunterApi(yufa, page, size)
            allsize1 = int(allsize1) if allsize1 != '' else 0
            allsize2 = int(allsize2) if allsize2 != '' else 0
            allsize = allsize1 + allsize2
            resultList = resultList1 + resultList2
        else:
            messagebox.showinfo(title='提示', message='请选择数据来源!')
            return
        if len(resultList) == 0:
            messagebox.showinfo(title='提示', message='未找到数据!')
            return
        # 清空数据
        self.del_tree()
        # 删除总条数
        delText(self.text_5)
        # 数据总条数
        self.text_5.configure(state="normal")
        self.text_5.insert(END, allsize)
        self.text_5.configure(state="disabled")
        # 写入数据
        index = 1
        flag = round(1000/len(resultList), 2)
        for one_of_list in resultList:
            self.tree.insert("","end",values=(
                        index,
                        one_of_list[0],
                        one_of_list[1],
                        one_of_list[2],
                        one_of_list[3],
                        one_of_list[4],
                        one_of_list[5]+'/'+one_of_list[6],
                        '未知',
                        one_of_list[7],
                        )
                    )
            index += 1
            # 进度条增长
            self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
    
    def fofaApi(self, yufa, page, size):
        import base64
        """ fofa查询 """
        email = GlobalVar.get_value('FOFA_EMAIL')
        key = GlobalVar.get_value('FOFA_KEY')

        url = 'https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&page={}&size={}&fields={}'
        try:
            resp_data = WebRequest().get(
                url=url.format(email, key, base64.b64encode(yufa.encode()).decode(), page, size, 'host,ip,port,protocol,title,country_name,city'),
                allow_redirects=False, 
                timeout=10).json
            allsize = resp_data.get('size')
            fofalist = resp_data.get('results')
            fofalist = [one + ['fofa'] for one in fofalist]
            return allsize,fofalist
        except Exception as error:
            Logger.error('[资产空间][fofa查询] '+ str(error))
            return '', []
            
    def hunterApi(self, yufa, page, size):
        from urllib.parse import quote
        import base64
        import datetime
        """ hunter查询 """
        key = GlobalVar.get_value('QIANXIN_API')
        qbase64 = base64.b64encode(yufa.encode()).decode()
        # 资产类型，1代表”web资产“，2代表”非web资产“，3代表”全部“
        is_web = 3
        # 状态码200
        # status_code = 200
        # 现在时间
        end_time = datetime.datetime.now()
        # 一年前时间
        start_time = str(int(end_time.strftime("%Y")) - 1) + "-" + end_time.strftime("%m-%d %H:%M:%S")
        # url编码
        end_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
        start_time = quote(start_time)
        end_time = quote(end_time)

        url = 'https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page={}&page_size={}&is_web={}&start_time={}&end_time={}'
        try:
            resp_data = WebRequest().get(
                url=url.format(key, qbase64, page, size, is_web, start_time, end_time),
                allow_redirects=False, 
                timeout=10).json
            # print(resp_data)
            allsize = resp_data.get('data').get('total')
            hunterlist = resp_data.get('data').get('arr')
            # 数据临时存储
            templist = []
            for one in hunterlist:
                host = one.get('url', '')
                ip = one.get('ip', '')
                port= one.get('port', '')
                protocol = one.get('protocol', '')
                title = one.get('web_title', '')
                country = one.get('country', '')
                city = one.get('city', '')
                templist.append([host, ip, port, protocol, title, country, city, 'hunter'])
            return allsize,templist
        except Exception as error:
            Logger.error('[资产空间][hunter查询] '+ str(error))
            return '', []

    ##右键鼠标事件
    def treeviewClick(self, event, menubar):
        try:
            menubar.delete(0,END)
            menubar.add_command(label='复制', command=lambda:self.copy_select(event))
            menubar.add_command(label='删除', command=lambda:self.del_select())
            menubar.add_command(label='清空', command=lambda:self.del_tree())
            menubar.add_command(label='识别CMS', command=lambda:self.thread_it(self.WhatCMS))
            menubar.add_command(label='漏洞扫描', command=lambda:self.autocheck())
            menubar.add_command(label='导入目标', command=lambda:self.Import2Target())
            menubar.post(event.x_root,event.y_root)
        except Exception as e:
            messagebox.showinfo(title='错误', message=e)

    #验证选中
    def autocheck(self, flag='', cmd='echo {}'.format(GlobalVar.get_value('flag')), vuln='False'):
        # 进度条初始化
        GlobalVar.get_value('exp').frame_progress.pBar["value"] = 0
        # 输出重定向到漏扫界面
        sys.stdout = TextRedirector(GlobalVar.get_value('exp').TexBOT_1_2, "stdout", index="exp")
        try:
            # 命令执行检测代理
            if Proxy_CheckVar1.get() == 0:
                if messagebox.askokcancel('提示','程序检测到未挂代理进行扫描,请确认是否继续?') == False:
                    print("[-]扫描已取消!")
                    return
            #验证前清空列表
            Zichanspace.vulns.clear()
            Zichanspace.kwargs.clear()
            Zichanspace.items.clear()
            #探测所有
            if flag == 'ALL':
                x = self.tree.get_children()
            #探测所选
            else:
                x = self.tree.selection()
            for item in x:
                item_text = self.tree.item(item,"values")
                # 非HTTP协议
                if 'http' not in item_text[4]:
                    continue
                if 'http' not in item_text[1] or 'https' not in item_text[1]:
                    target = item_text[4] + '://' + item_text[1]
                else:
                    # 输出所选行的第2列的值
                    target = item_text[1]
                # 获取CMS名称
                appName = item_text[7]
                if appName not in exp_scripts:
                    continue
                # 测试所有模块
                pocname = 'ALL'
                try:
                    Zichanspace.vulns.append(importlib.import_module('.%s'%appName, package='EXP'))
                    Zichanspace.kwargs.append({
                        'url' : target,
                        'cookie' : '',
                        'cmd' : cmd,
                        'pocname' : pocname,
                        'vuln' : vuln,
                        'timeout' : int(Ent_B_Top_timeout.get()),
                        'retry_time' : int(Ent_B_Top_retry_time.get()),
                        'retry_interval' : int(Ent_B_Top_retry_interval.get()),
                    })
                    #HTTP协议item入列表
                    Zichanspace.items.append(item)
                except Exception as error:
                    Logger.error('[资产空间][漏扫] '+ str(error))
            self.thread_it(self.exeCMD,**{
                'pool_num' : int(Ent_B_Top_thread_pool.get())
            })
        except Exception as error:
            Logger.error('[资产空间][漏扫] '+ str(error))

    def exeCMD(self, **kwargs):
        from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
        if len(Zichanspace.vulns) == 0:
            messagebox.showinfo(title='提示', message='未选中目标,请检查是否选中目标,且已提前识别CMS!')
            return
        # 界面重定向到漏扫界面
        screens = GlobalVar.get_value('screens')
        for screen in screens:
            screen.pack_forget()
        self.gui.frmEXP.pack(side=BOTTOM, expand=1, fill=BOTH)
        start = time.time()
        flag = round(800/len(Zichanspace.items), 2)
        #初始化全局子线程列表
        pool = ThreadPoolExecutor(kwargs['pool_num'])
        GlobalVar.set_value('thread_list', [])
        print("[*]开始执行测试......本次扫描参数如下:\n->线程数量: %s \n->超时时间: %s \n->请求次数: %s \n->重试间隔: %s"%(str(kwargs['pool_num']), Zichanspace.kwargs[0]['timeout'], Zichanspace.kwargs[0]['retry_time'], Zichanspace.kwargs[0]['retry_interval']))
        for index in range(len(Zichanspace.vulns)):
            Zichanspace.kwargs[index]['pool'] = pool
            Zichanspace.vulns[index].check(**Zichanspace.kwargs[index])
            # 加载脚本进度条
            GlobalVar.get_value('exp').frame_progress.pBar["value"] = GlobalVar.get_value('exp').frame_progress.pBar["value"] + flag
        # 依次等待线程执行完毕
        wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
        # 总共加载的poc数
        total_num = 0
        # 根据结果更改值
        index = 0
        # 成功次数
        success_num = 0
        for future in GlobalVar.get_value('thread_list'):
            # 去除取消掉的future任务
            if future.cancelled() == False:
                #成功
                if 'success' in future.result():
                    # self.tree.item(Zichanspace.items[index], tags='tag_success')
                    success_num += 1
                    # 插入仓库
                    i = future.result().split("|")
                    # 根据返回值生成一条扫描记录
                    from module import ScanRecord
                    scan_one_record = ScanRecord(
                        target = i[0],
                        appName = i[1],
                        pocname = i[2],
                        last_status = i[3],
                        last_time = i[4],
                    )
                    # 插入扫描记录
                    GlobalVar.get_value('myvuldatabase').tree.insert("","end",values=(
                        '999',
                        scan_one_record.target,
                        scan_one_record.appName,
                        scan_one_record.pocname,
                        scan_one_record.last_status,
                        scan_one_record.last_time,
                        )
                    )
                # #失败
                # else:
                #     self.tree.item(Zichanspace.items[index], tags='tag_fail')
            index += 1
            total_num += 1
        end = time.time()
        # 执行完成
        GlobalVar.get_value('exp').frame_progress.pBar["value"] += 200
        # 关闭线程池
        pool.shutdown()
        print('[*]共花费时间：%s 秒 , 共检测数量: %s , 漏洞数量: %s'%(seconds2hms(end - start),str(total_num),str(success_num)))

    # 识别CMS
    def WhatCMS(self):
        import importlib,time
        Zichanspace.items.clear()
        Zichanspace.url_list.clear()
        result_list = []
        # 进度条初始化
        self.frame_progress.pBar["value"] = 0
        for item in self.tree.selection():
            item_text = self.tree.item(item,"values")
            # 非HTTP协议
            if 'http' not in item_text[4]:
                continue
            if 'http' not in item_text[1] or 'https' not in item_text[1]:
                fileURL = item_text[4] + '://' + item_text[1]
            else:
                # 输出所选行的第2列的值
                fileURL = item_text[1]
            Zichanspace.items.append(item)
            Zichanspace.url_list.append(fileURL)
        
        # 此次任务没有目标
        if len(Zichanspace.url_list) == 0:
            messagebox.showinfo(title='错误', message='只能识别HTTP协议的站点噢:)')
            return

        # 完成一次增长的长度
        flag = round(1000/len(Zichanspace.url_list), 2)
        # 导入函数
        vuln = importlib.import_module('.GetCMS', package='POC')
        # 开始时间
        start = time.time()
        
        # 线程池大小
        from concurrent.futures import ThreadPoolExecutor
        executor = ThreadPoolExecutor(max_workers = 10)
        for data in executor.map(lambda kwargs: vuln.api(kwargs), Zichanspace.url_list):
            # 汇聚结果
            result_list.append(data)
            # 进度条
            self.frame_progress.pBar["value"] = self.frame_progress.pBar["value"] + flag
        # 设置结果值
        for index in range(len(Zichanspace.items)):
            self.tree.set(Zichanspace.items[index], column='cms', value=result_list[index])
        # 关闭线程池
        executor.shutdown()
        # 结束时间
        end = time.time()
        messagebox.showinfo(title='提示', message='识别完成, 共花费时间: {} 秒'.format(seconds2hms(end - start)))
        
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

    def Import2Target(self):
        myurls = GlobalVar.get_value('myurls')
        # 清空目标
        # myurls.TexA.delete('1.0','end')
        for item in self.tree.selection():
            item_text = self.tree.item(item,"values")
            # 非HTTP协议
            if 'http' not in item_text[4]:
                ip = item_text[2]
                myurls.TexA.insert(INSERT, ip + '\n')
                continue
            if 'http' not in item_text[1] or 'https' not in item_text[1]:
                fileURL = item_text[4] + '://' + item_text[1]
            else:
                # 输出所选行的第2列的值
                fileURL = item_text[1]
            myurls.TexA.insert(INSERT, fileURL + '\n')
        
    def openurl(self):
        import os
        import webbrowser
        for item in self.tree.selection():
            item_text = self.tree.item(item,"values")
            if 'http' not in item_text[4]:
                return
            if 'http' not in item_text[1] or 'https' not in item_text[1]:
                fileURL = item_text[4] + '://' + item_text[1]
            else:
                # 输出所选行的第2列的值
                fileURL = item_text[1]
            '''
            Save as HTML file and open in the browser
            '''
            hide = os.dup(1)
            os.close(1)
            os.open(os.devnull, os.O_RDWR)
            try:
                webbrowser.open(fileURL)
            except Exception as e:
                print("Output can't be saved in %s \
                    due to exception: %s" % (fileURL, e))
            finally:
                os.dup2(hide, 1)

    def fixed_map(self, option):
        return [elm for elm in self.style.map('Treeview', query_opt=option) if elm[:2]!=('!disabled','!selected')]

    # 删除选中的行
    def del_select(self):
        for selected_item in self.tree.selection():
            self.tree.delete(selected_item)

    # 清空所有
    def del_tree(self):
        x = self.tree.get_children()
        for item in x:
            self.tree.delete(item)

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func, kwargs=kwargs)
        self.t.setDaemon(True)
        self.t.start()

    def start(self):
        self.CreateFrm()
        self.CreatTop()
        self.CreatMiddle()
        self.CreatBottom()