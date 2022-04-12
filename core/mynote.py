from tkinter import Frame,scrolledtext
from tkinter import INSERT,X

class Mynote():
    def __init__(self, gui):
        self.frmNote = gui.frmNote
        self.root = gui.root

    def CreateFrm(self):
        self.frm = Frame(self.frmNote, width=1160, height=700, bg='white')
        self.frm.grid_propagate(0)
        self.frm.grid(row=0, column=0, padx=1, pady=1)
        
        self.Text_note = scrolledtext.ScrolledText(self.frm, font=("consolas",10), width=125, height=33)
        self.Text_note.pack(fill=X, expand=1)
        
        with open('note.txt', mode='r', encoding='utf-8') as f:
            array = f.readlines()
            #遍历array中的每个元素
            for i in array:
                self.Text_note.insert(INSERT, i)

    def start(self):
        self.CreateFrm()