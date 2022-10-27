# -*- coding: utf-8 -*-
from tkinter import Frame,scrolledtext
from tkinter import INSERT,X,BOTH

class Mynote():
    def __init__(self, gui):
        self.frmNote = gui.frmNote
        self.root = gui.root

    def CreateFrm(self):
        self.frm = Frame(self.frmNote, width=1160, height=700, bg='white')
        self.frm.pack(expand=1, fill=BOTH)
        
        self.Text_note = scrolledtext.ScrolledText(self.frm, font=("consolas",10), width=125, height=33)
        self.Text_note.pack(expand=1, fill=BOTH)
        
        with open('log/note.txt', mode='r', encoding='utf-8') as f:
            array = f.readlines()
            # 遍历array中的每个元素
            for i in array:
                self.Text_note.insert(INSERT, i)

    # 保存当前数据
    def save(self):
        save_data = str(self.Text_note.get('0.0','end'))[0:-1]
        with open('log/note.txt', mode='w', encoding='utf-8', errors='ignore') as f:
            f.write(save_data)
            
    def start(self):
        self.CreateFrm()