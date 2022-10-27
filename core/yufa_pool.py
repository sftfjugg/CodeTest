# -*- coding: utf-8 -*-
from tkinter import Toplevel,Frame,Menu,Label,ttk,Button,Scrollbar,Entry
from tkinter import END,W,BOTH,Y,LEFT,RIGHT
from settings import rootPath,Ent_O_Top_yufakey,Ent_O_Top_yufa,Ent_O_Top_source
from ClassCongregation import addToClipboard
import threading
class Yufa_pool():
    def __init__(self, gui):
        self.gui = gui
        self.Yufa = Toplevel(gui.root)
        self.Yufa.title("FOFA语法")
        self.Yufa.geometry('1000x400+650+150')
        self.Yufa.iconbitmap('python.ico')
        #不允许扩大
        self.exchange = self.Yufa.resizable(width=False, height=False)
        #创建一个菜单
        self.menubar = Menu(self.Yufa, tearoff=False)
        self.columns = ("index", "name", "keys")

        self.frmA = Frame(self.Yufa, width=1000, height=35, bg="whitesmoke")
        self.frmB = Frame(self.Yufa, width=1000, height=365, bg="red")
        
        self.frmA.grid(row=0, column=0, padx=1, pady=1)
        self.frmB.grid(row=1, column=0, padx=1, pady=1)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)

        self.label_1 = Label(self.frmA, text="CMS关键字")
        self.EntA_1 = Entry(self.frmA, width='85', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_yufakey, font=("consolas",10))        
        self.label_1.grid(row=0, column=0, padx=1, pady=1, sticky=W)
        self.EntA_1.grid(row=0, column=1, padx=1, pady=1, sticky=W)

        #查询按钮
        self.buttonA = Button(self.frmA, text="查询", width=5, command=lambda :self.thread_it(self.search))
        self.buttonB = Button(self.frmA, text="重置", width=5, command=lambda :self.thread_it(self.reset))
        
        self.buttonA.grid(row=0, column=2, padx=1, pady=1, sticky=W)
        self.buttonB.grid(row=0, column=3, padx=1, pady=1, sticky=W)

        self.ybar = Scrollbar(self.frmB, orient='vertical')
        self.tree = ttk.Treeview(self.frmB, height=16, columns=self.columns, show="headings",yscrollcommand=self.ybar.set)
        self.ybar['command'] = self.tree.yview
        #绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, self.menubar))
        # 绑定左键双击事件
        self.tree.bind("<Double-1>", lambda x: self.setYufa())
        self.tree.heading("index", text="序号", command=lambda :self.treeview_sort_column(self.tree, 'name', False))
        self.tree.heading("name", text="CMS名称", command=lambda :self.treeview_sort_column(self.tree, 'name', False))
        self.tree.heading("keys", text="搜索语法", command=lambda :self.treeview_sort_column(self.tree, 'keys', False))
        # 定义各列列宽及对齐方式
        self.tree.column("index", width=60, anchor="center")
        self.tree.column("name", width=250, anchor="w")
        self.tree.column("keys", width=650, anchor="w")

        # 右边的滚动在Y轴充满
        self.ybar.pack(side=RIGHT, fill=Y)
        self.tree.pack(side=LEFT , fill=BOTH)
        #关联回调函数
        self.Yufa.protocol("WM_DELETE_WINDOW", self.close)

    def hide(self):
        """
        隐藏界面
        """
        self.Yufa.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.Yufa.update()
        self.Yufa.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()

    #清空所有
    def del_tree(self):
        x = self.tree.get_children()
        for item in x:
            self.tree.delete(item)

    #删除选中的行
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
    
    #重置
    def reset(self):
        Ent_O_Top_yufakey.set('')
        self.del_tree()

    #设置语法
    def setYufa(self):
        Ent_O_Top_source.set('fofa')
        for item in self.tree.selection():
            item_text = self.tree.item(item,"values")
            Ent_O_Top_yufa.set(item_text[2])

    #查询
    def search(self):
        import sqlite3
        #清除上一次结果
        self.del_tree()
        yufakey = Ent_O_Top_yufakey.get().strip('\n')
        with sqlite3.connect(rootPath+'/cms_finger.db') as conn:
            cursor = conn.cursor()
            result = cursor.execute("SELECT name, keys FROM `tide` WHERE name LIKE '%{}%'".format(yufakey))
            index = 1
            for row in result:
                self.tree.insert("","end",values=(
                            index,
                            row[0],
                            row[1],
                            )
                        )
                index += 1
            result = cursor.execute("SELECT name, keys FROM `fofa_back` WHERE name LIKE '%{}%'".format(yufakey))
            for row in result:
                self.tree.insert("","end",values=(
                            index,
                            row[0],
                            row[1],
                            )
                        )
                index += 1
                
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

    #右键鼠标事件
    def treeviewClick(self, event, menubar):
            menubar.delete(0,END)
            menubar.add_command(label='复制', command=lambda:self.copy_select(event))
            menubar.add_command(label='删除', command=self.del_select)
            menubar.add_command(label='清空', command=self.del_tree)
            menubar.add_command(label='使用当前语法', command=self.setYufa)
            menubar.post(event.x_root,event.y_root)

    #多线程执行函数
    def thread_it(self, func, **kwargs):
        self.t = threading.Thread(target=func, kwargs=kwargs, name='执行函数子线程')
        self.t.setDaemon(True)   # 守护
        self.t.start()           # 启动