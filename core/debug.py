# -*- coding: utf-8 -*-
from ClassCongregation import delText
from tkinter import Frame,scrolledtext,Menu
from tkinter import X,END,INSERT,BOTH

class Debug():
    def __init__(self, gui):
        self.frmDebug = gui.frmDebug
        self.root = gui.root
        # 创建一个菜单
        self.menubar = Menu(self.root, tearoff=False)

    def CreateFrm(self):
        # 创建顶级菜单
        self.frm = Frame(self.frmDebug, width=1160, height=700, bg='white')
        self.frm.pack(expand=1, fill=BOTH)
        
        self.Debug_note = scrolledtext.ScrolledText(self.frm, font=("consolas",10), width=125, height=33)
        self.Debug_note.pack(expand=1, fill=BOTH)
        # 绑定右键鼠标事件
        self.Debug_note.bind("<Button-3>", lambda x: self.rightKey(x, self.menubar))
        # self.Debug_note.insert(INSERT, "123")
        with open('log/debug.log', mode='r', encoding='utf-8') as f:
            array = f.readlines()
            # 遍历array中的每个元素
            for i in array:
                self.Debug_note.insert(INSERT, i)
        self.Debug_note.configure(state="disabled")

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        menubar.add_command(label='清空信息', command=lambda : delText(self.Debug_note))
        menubar.post(event.x_root,event.y_root)

    # 保存当前数据
    def save(self):
        save_data = str(self.Debug_note.get('0.0','end'))[0:-1]
        with open('log/debug.log', mode='w', encoding='utf-8', errors='ignore') as f:
            f.write(save_data)

    def start(self):
        self.CreateFrm()