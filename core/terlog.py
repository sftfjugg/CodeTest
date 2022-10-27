from ClassCongregation import delText
from tkinter import Frame,scrolledtext,Menu
from tkinter import X,END,INSERT

class Terlog():
    def __init__(self, gui):
        self.frmTerlog = gui.frmTerlog
        self.root = gui.root
        self.menubar = Menu(self.root, tearoff=False)#创建一个菜单

    def CreateFrm(self):
        #创建顶级菜单
        self.frm = Frame(self.frmTerlog, width=1160, height=700, bg='white')
        self.frm.grid_propagate(0)
        self.frm.grid(row=0, column=0, padx=1, pady=1)
        
        self.Terlog_note = scrolledtext.ScrolledText(self.frm, font=("consolas", 10), width=125, height=33)
        self.Terlog_note.pack(fill=X, expand=1)
        #绑定事件
        self.Terlog_note.bind("<Button-3>", lambda x: self.rightKey(x, self.menubar))#绑定右键鼠标事件
        # self.Debug_note.insert(INSERT, "123")
        with open('log/terlog.log', mode='r', encoding='utf-8') as f:
            array = f.readlines()
            #遍历array中的每个元素
            for i in array:
                self.Terlog_note.insert(INSERT, i)
        self.Terlog_note.configure(state="disabled")

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        menubar.add_command(label='清空信息', command=lambda : delText(self.Terlog_note))
        menubar.post(event.x_root,event.y_root)

    #保存当前数据1
    def save(self):
        save_data = str(self.Terlog_note.get('0.0','end'))[0:-1]
        with open('log/terlog.log', mode='w', encoding='utf-8', errors='ignore') as f:
            f.write(save_data)

    def start(self):
        self.CreateFrm()