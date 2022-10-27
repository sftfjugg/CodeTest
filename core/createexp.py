# -*- coding: utf-8 -*-
from settings import Ent_C_Top_vulname,Ent_C_Top_cmsname,Ent_C_Top_cvename,Ent_C_Top_version,Ent_C_Top_info,Ent_C_Top_template, \
    Ent_C_Top_url,Ent_C_Top_path,Ent_C_Top_reqmethod, \
    exp_scripts
from tkinter import LEFT, Toplevel,Frame,Label,Entry,ttk,Button,Text,messagebox,scrolledtext
from tkinter import S,W,E,X,Y,N,INSERT,BOTH,RIGHT,TOP,BOTTOM,NONE
from core.yamlfile import YamlFile
from jinja2 import Environment, PackageLoader
from urllib.parse import urlparse
import math
# 根据模板生成EXP类
class CreateExp():
    def __init__(self, gui):
        self.Creat = Toplevel(gui.root)
        self.Creat.title("EXP生成")
        self.Creat.geometry('1060x650+480+20')
        self.Creat.iconbitmap('python.ico')
        # 不允许扩大
        # self.Creat.resizable(width=False, height=False)
        self.columns = ("变量", "操作", "值", "逻辑")
        self.variable = []
        self.operation = []
        self.Value = []
        self.logic = []

        # 左边
        self.frm_A = Frame(self.Creat, width=520, height=650, bg="whitesmoke")
        # 右边
        self.frm_B = Frame(self.Creat, width=540, height=650, bg="whitesmoke")
        self.frm_A.pack(side=LEFT, expand=1, fill=BOTH)
        self.frm_B.pack(side=RIGHT, expand=1, fill=BOTH)

        # 左上
        self.frm_A_1 = Frame(self.frm_A, width=520, height=330, bg="whitesmoke")
        # 左下
        self.frm_A_2 = Frame(self.frm_A, width=520, height=320, bg="whitesmoke")
        self.frm_A_1.pack(side=TOP, expand=0, fill=X)
        self.frm_A_2.pack(side=BOTTOM, expand=1, fill=BOTH)
        
        # 显示
        self.Lab_A_1_1 = Label(self.frm_A_1, text='脚本名称(类名)')
        # 接受输入控件
        self.Ent_A_1_1 = Entry(self.frm_A_1, width=35, highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_vulname)
        self.Lab_A_1_1.grid(row=0, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_1.grid(row=0, column=1,padx=20, pady=10, sticky=W)
        
        # 显示
        self.Lab_A_1_2 = Label(self.frm_A_1, text='CMS名称')
        # 接受输入控件
        self.Ent_A_1_2 = Entry(self.frm_A_1, width=35, highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_cmsname)
        self.Lab_A_1_2.grid(row=1, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_2.grid(row=1, column=1,padx=20, pady=10, sticky=W)
        
        # 显示
        self.Lab_A_1_3 = Label(self.frm_A_1, text='CVE编号(函数名)')
        # 接受输入控件
        self.Ent_A_1_3 = Entry(self.frm_A_1, width=35, highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_cvename)
        self.Lab_A_1_3.grid(row=2, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_3.grid(row=2, column=1,padx=20, pady=10, sticky=W)
        
        # 显示
        self.Lab_A_1_4 = Label(self.frm_A_1, text='版本信息\漏洞描述')
        # 接受输入控件
        self.Ent_A_1_4 = Entry(self.frm_A_1, width=35, highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_version)
        self.Lab_A_1_4.grid(row=3, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_4.grid(row=3, column=1,padx=20, pady=10, sticky=W)

        # 显示
        self.Lab_A_1_5 = Label(self.frm_A_1, text='info')
        # 接受输入控件
        self.comboxlist_A_1_4 = ttk.Combobox(self.frm_A_1,width=20,textvariable=Ent_C_Top_info,state='readonly')
        self.comboxlist_A_1_4["values"] = tuple(["[rce]","[deserialization rce]",
                                            "[upload]",
                                            "[deserialization upload]",
                                            "[deserialization]",
                                            "[file contains]",
                                            "[file reading]",
                                            "[xxe]",
                                            "[sql]",
                                            "[ssrf]"])
        self.Lab_A_1_5.grid(row=4, column=0,padx=20, pady=10, sticky=W)
        self.comboxlist_A_1_4.grid(row=4, column=1,padx=20, pady=10, sticky=W)

        #左下左
        self.frm_A_2_1 = Frame(self.frm_A_2, width=430, height=320,bg='whitesmoke')
        #左下右
        self.frm_A_2_2 = Frame(self.frm_A_2, width=90, height=320,bg='whitesmoke')
        self.frm_A_2_1.pack(side=LEFT, expand=1, fill=BOTH)
        self.frm_A_2_2.pack(side=RIGHT, expand=0, fill=Y)
        
        # 表格
        self.treeview_A_2 = ttk.Treeview(self.frm_A_2_1, height=16, show="headings", columns=self.columns)
        self.treeview_A_2.column("变量", width=90, anchor='w')
        self.treeview_A_2.column("操作", width=90, anchor='w')
        self.treeview_A_2.column("值", width=200, anchor='w')
        self.treeview_A_2.column("逻辑", width=50, anchor='w')
        self.treeview_A_2.heading("变量", text="变量")
        self.treeview_A_2.heading("操作", text="操作")
        self.treeview_A_2.heading("值", text="值")
        self.treeview_A_2.heading("逻辑", text="逻辑")
        # 双击左键进入编辑
        self.treeview_A_2.bind('<Double-Button-1>', self.set_cell_value)
        self.treeview_A_2.pack(expand=1, fill=BOTH)
        
        self.button_1 = Button(self.frm_A_2_2, text='<-添加', width=10, command=self.newrow)
        self.button_2 = Button(self.frm_A_2_2, text='<-删除', width=10, command=self.deltreeview)
        self.button_1.grid(row=0, column=0, padx=1, pady=1, sticky='n')
        self.button_2.grid(row=1, column=0, padx=1, pady=1, sticky='n')

        self.frm_B_1 = Frame(self.frm_B, width=540, height=40, bg="whitesmoke")
        self.frm_B_2 = Frame(self.frm_B, width=540, height=610, bg="whitesmoke")
        self.frm_B_1.pack(side=TOP, expand=0, fill=X)
        self.frm_B_2.pack(side=TOP, expand=1, fill=BOTH)
        
        # 接受输入控件
        self.comboxlist_B = ttk.Combobox(self.frm_B_1,width=20,textvariable=Ent_C_Top_template,state='readonly')
        self.comboxlist_B['values'] = tuple(['POC','EXP'])
        self.comboxlist_B.bind("<<ComboboxSelected>>", self.SelectTemplate)
        self.button_3 = Button(self.frm_B_1, text='生成EXP', width=6, command=self.Creat_from_temp)
        self.button_4 = Button(self.frm_B_1, text='保存EXP', width=6, command=self.Save_from_temp)
        self.button_5 = Button(self.frm_B_1, text='导入xray', width=6, command=lambda:YamlFile(self.Creat,self.text_B))
        
        self.comboxlist_B.pack(side=LEFT, expand=0, fill=X)
        self.button_3.pack(side=LEFT, expand=0, fill=X)
        self.button_4.pack(side=LEFT, expand=0, fill=X)
        self.button_5.pack(side=LEFT, expand=0, fill=X)
        
        self.text_B = scrolledtext.ScrolledText(self.frm_B_2, font=("consolas", 9), width=63, height=33)
        self.text_B.pack(expand=1, fill=BOTH)
        # 关联回调函数
        self.Creat.protocol("WM_DELETE_WINDOW", self.close)

    def hide(self):
        """
        隐藏界面
        """
        self.Creat.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.Creat.update()
        self.Creat.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()
        
    def Creat_from_temp(self):
        import util.globalvar as GlobalVar
        mycheck = GlobalVar.get_value('mycheck')
        try:
            self.text_B.delete('1.0','end')
            env = Environment(loader=PackageLoader('Template', './'))
            template = env.get_template(self.comboxlist_B.get()+'.j2')
            url = Ent_C_Top_url.get().strip('\n') + Ent_C_Top_path.get().strip('\n')
            if url == '':
                messagebox.showinfo(title='提示', message='没有获取到URL')
                return
            header = dict(zip(mycheck.Type, mycheck.Value))
            headers = {}
            for key, value in header.items():
                if key and value:
                    headers.update({key : value})

            temp_1 = {'Code':'str(r.status_code)', 'HTTP返回头':'str(r.headers)', 'HTTP返回正文':'r.text'}
            temp_2 = {'包含': 'in', 'Not Contains':'not in'}

            var = [temp_1[i] if i in temp_1 else i for i in self.variable]
            oper = [temp_2[i] if i in temp_2 else i for i in self.operation]

            str_2 = ''
            
            for i in range(len(self.Value)):
                if self.logic[i] == None:
                    continue
                elif self.logic[i] == '':
                    str_1 = "r\"" + self.Value[i] + "\"" + " " + oper[i] + " " + var[i]
                    str_2 = str_2 + str_1
                    break
                else:
                    str_1 = "r\"" + self.Value[i] + "\"" + " " + oper[i] + " " + var[i] + " " + self.logic[i].lower() + " "
                    str_2 = str_2 + str_1
            str_2 = "if "+str_2+":"

            service={
                        "entry_nodes":
                            {
                                "vulname": Ent_C_Top_vulname.get().replace(' ','').strip('\n'),
                                "cmsname": Ent_C_Top_cmsname.get().replace(' ','').strip('\n'),
                                "cvename": Ent_C_Top_cvename.get().replace(' ','').strip('\n'),
                                "banner": Ent_C_Top_version.get().strip('\n'),
                                "infoname": Ent_C_Top_info.get(),
                                "condition": str_2.strip('\n')
                            },
                        "header_nodes":
                            {
                                "headinfo":
                                    {
                                        "method": Ent_C_Top_reqmethod.get().lower(),
                                        "path": url[url.index(urlparse(url).netloc)+len(urlparse(url).netloc):],
                                        "header": headers
                                    },
                                "content":
                                    {   "data": mycheck.Text_post.get('0.0','end').strip('\n').replace('\n','\\n')}
                                
                            }
                    }
            content = template.render(service=service)
            self.text_B.insert(INSERT, content)
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)

    def Save_from_temp(self):
        global exp_scripts
        save_data = str(self.text_B.get('0.0','end').strip('\n'))
        if save_data == '':
            messagebox.showinfo(title='提示', message='没有数据')
            return
        if Ent_C_Top_vulname.get() == '':
            messagebox.showinfo(title='提示', message='请单独输入要保存的脚本名称(类名)')
            return
        try:
            fobj_w = open('./EXP/'+Ent_C_Top_vulname.get()+'.py', 'w',encoding='utf-8')
            fobj_w.writelines(save_data)
            fobj_w.close()
            exp_scripts.append(Ent_C_Top_vulname.get())
            #exp.comboxlist_3["values"] = tuple(exp_scripts)
            messagebox.showinfo(title='结果', message='保存成功')
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)


    def SelectTemplate(self,event):
        self.Template_name = './Template/'+self.comboxlist_B.get()+'.j2'
        self.text_B.delete('1.0','end')
        try:
            with open(self.Template_name, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                for i in array: #遍历array中的每个元素
                    self.text_B.insert(INSERT, i)
        except FileNotFoundError as error:
            messagebox.showinfo(title='文件未找到', message=error)
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)
            
    def set_cell_value(self, event):
        item_text = None
        for self.item in self.treeview_A_2.selection():
        #item = I001
            item_text = self.treeview_A_2.item(self.item, "values")
	
        #print(item_text[0:2])  # 输出所选行的值
        self.column= self.treeview_A_2.identify_column(event.x)# 列
        cn = int(str(self.column).replace('#',''))
        rn = math.floor(math.floor(event.y-25)/18)+1

        if cn == 4 and item_text:
            self.tempCom = ttk.Combobox(self.frm_A_2_1, font=("consolas",10), state='readonly')
            self.tempCom['values'] = tuple(['AND','OR',''])
            self.tempCom.current(0)
            self.tempCom.bind("<<ComboboxSelected>>", self.saveCom)

            self.tempCom.place(x=2*self.treeview_A_2.column("变量")["width"]+self.treeview_A_2.column("值")["width"],
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)
        elif cn == 3 and item_text:
            self.entryedit = Text(self.frm_A_2_1, font=("consolas",10))
            self.entryedit.insert(INSERT, item_text[cn-1])
            self.entryedit.bind('<FocusOut>',self.saveentry)
            self.entryedit.place(x=2*self.treeview_A_2.column("变量")["width"],
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)
        elif cn == 2 and item_text:
            self.tempCom = ttk.Combobox(self.frm_A_2_1, font=("consolas",10), state='readonly')
            self.tempCom['values'] = tuple(['包含','Not Contains','==','!=','>','<','>=','<='])
            self.tempCom.current(0)
            self.tempCom.bind("<<ComboboxSelected>>", self.saveCom)

            self.tempCom.place(x=self.treeview_A_2.column("变量")["width"],
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)
        elif cn == 1 and item_text:
            self.tempCom = ttk.Combobox(self.frm_A_2_1, font=("consolas",10), state='readonly')
            self.tempCom['values'] = tuple(['Code','HTTP返回头','HTTP返回正文'])
            self.tempCom.current(0)
            self.tempCom.bind("<<ComboboxSelected>>", self.saveCom)

            self.tempCom.place(x=0,
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)

    def saveentry(self,event):
        try:
            self.treeview_A_2.set(self.item, column=self.column, value=self.entryedit.get(0.0, "end").replace('\n',''))
            #a = self.tempCom.get()
            self.Value[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')

        except Exception as error:
            messagebox.showinfo(title='提示', message=error)
        finally:
            self.entryedit.destroy()

    def saveCom(self, event):
        try:
            self.treeview_A_2.set(self.item, column=self.column, value=self.tempCom.get())
            #a = self.tempCom.get()
            if self.column.replace('#','') == '1':
                self.variable[int(self.item.replace('I00',''))-1] = self.tempCom.get()
            elif self.column.replace('#','') == '2':
                self.operation[int(self.item.replace('I00',''))-1] = self.tempCom.get()
            elif self.column.replace('#','') == '4':
                self.logic[int(self.item.replace('I00',''))-1] = self.tempCom.get()

        except Exception as error:
            messagebox.showinfo(title='提示', message=error)
        finally:
            self.tempCom.destroy()

    def newrow(self):
        self.variable.append('')
        self.operation.append('')
        self.Value.append('')
        self.logic.append('')
        # 解决BUG, insert函数如果不指定iid, 则会自动生成item标识, 此操作不会因del而回转
        try:
            self.treeview_A_2.insert('', 'end',
                            iid='I00'+str(len(self.variable)),
                            values=(self.variable[len(self.variable)-1], 
                            self.operation[len(self.variable)-1],
                            self.Value[len(self.variable)-1],
                            self.logic[len(self.variable)-1]))
            self.treeview_A_2.update()
        except Exception as e:
            self.variable.pop()
            self.operation.pop()
            self.Value.pop()
            self.logic.pop()

    def deltreeview(self):
        for self.item in self.treeview_A_2.selection():
            self.treeview_A_2.delete(self.item)
            self.variable[int(self.item.replace('I00',''))-1] = None
            self.operation[int(self.item.replace('I00',''))-1] = None
            self.Value[int(self.item.replace('I00',''))-1] = None
            self.logic[int(self.item.replace('I00',''))-1] = None