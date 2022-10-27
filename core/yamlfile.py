from tkinter import Toplevel,Frame,scrolledtext,messagebox
from tkinter import BOTH,INSERT
from util.fun import *
import yaml
"""
Yaml Editor
"""

yaml_template = '''
from util.ExpRequest import ExpRequest,Output
from util.fun import *
import util.globalvar as GlobalVar
import prettytable as pt
"""
from ClassCongregation import Dnslog,random_name
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class Xray_{vulname}():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = env.get('timeout')
        self.flag = GlobalVar.get_value('flag')

    def {cvename}(self):
        appName = 'Xray_{vulname}'
        pocname = '{cvename}'
        desc = '{infoname} {banner}'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            if self.vuln == 'False':
                {requests}
                if {expression}:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    'Xray_{vulname}',
    '{cvename}',
    '{infoname} {banner}'
])
print(tb)

def check(**kwargs):
    thread_list = []
    ExpXray_{vulname} = Xray_{vulname}(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpXray_{vulname}, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(Xray_{vulname}):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpXray_{vulname}, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)
'''

request_template = """
                path = '{path}'
                method = '{method}'
                body = '''{body}'''
                headers = {header}

                response = exprequest.{method}(
                    url=self.url+path, 
                    data=body, 
                    headers=headers, 
                    retry_time=self.retry_time, 
                    retry_interval=self.retry_interval,
                    timeout=self.timeout, 
                    verify=False
                    )
"""

class YamlFile():
    def __init__(self, root, text):
        self.yaml = Toplevel(root)
        self.text = text
        self.yaml.title("导入yaml")
        self.yaml.geometry('900x500+650+150')
        self.yaml.iconbitmap('python.ico')
        
        self.frmA = Frame(self.yaml, width=900, height=500,bg="white")
        self.frmA.pack(fill=BOTH, expand=1)
        
        self.TexA = scrolledtext.ScrolledText(self.frmA,font=("consolas", 9),undo = True)
        self.TexA.pack(fill=BOTH, expand=1)
        #关联回调函数
        self.yaml.protocol("WM_DELETE_WINDOW", self.close)
        
    def Creat_from_yaml_xray(self):
        global yaml_template,request_template
        yamlfile = self.TexA.get('0.0','end').strip('\n')
        #yamlfile = yamlfile.replace('response', 'r')
        #转化yaml数据为字典或列表
        yamldict = yaml.load(yamlfile, Loader=yaml.SafeLoader)
        #变量替换
        varname_list = []
        varvalue_list = []
        expression_dcit = {}
        #存在set变量
        if yamldict.get('set', None):
            varname_list = [key for key in yamldict.get('set', None).keys()]
            #循环赋值变量
            for j, k in yamldict.get('set', None).items():
                if len(yamldict.get('set', None)) == 1:
                    value = eval(k)
                    varvalue_list.append(value)
                    break
                for index in range(len(varname_list)):
                    if varname_list[index] in k:
                        if isinstance(varvalue_list[index], str):
                            k = k.replace(varname_list[index], '"'+varvalue_list[index]+'"')
                        else:
                            k = k.replace(varname_list[index], varvalue_list[index])
                value = eval(k)
                varvalue_list.append(value)
                #Globals[j] = value
        var_dcit = dict(zip(varname_list, varvalue_list))
        #字段值初始化
        path = None
        method = None
        body = None
        headers = None
        expression = None
        #传输协议: transport
        #tcp
        #udp
        #http
        if yamldict['transport'] == 'http':
            #函数名称: poc_yaml_74cms_sqli_1
            #poc_yaml_youphptube_encoder_cve_2019_5127
            cvename = yamldict['name'].replace(' ','').replace('-','_').replace('poc_yaml_', 'cve_')
            #漏洞描述、版本信息
            banner = cvename
            #类名和组件名称一样
            vulname  = cmsname = cvename.split('_')[1]
            #漏洞类型
            infoname = 'app="'+vulname+'"'
            #判断条件一: 随机值
            #flag = yamldict['set']['rand']
            
            #前置处理
            yaml_template = yaml_template.strip('\n')
            #替换函数名称
            yaml_template = yaml_template.replace('{cvename}', cvename)
            #替换类名
            yaml_template = yaml_template.replace('{vulname}', vulname)
            #替换组件名称
            yaml_template = yaml_template.replace('{cmsname}', cmsname)
            #替换版本信息
            yaml_template = yaml_template.replace('{banner}', banner)
            #替换漏洞类型
            yaml_template = yaml_template.replace('{infoname}', infoname)
        
            #多个请求
            temp = ''
            for key1, value1 in yamldict['rules'].items():
                #重置模板
                temp_request_template = request_template
                #output = value1['output']
                #for key3, value3 in value1['output'].items():
                req = value1['request']
                for key2, value2 in req.items():
                    #print(key, value)
                    if key2 == 'method':
                        method = value2.lower()
                    #path 替换变量
                    elif key2 == 'path':
                        for var in varname_list:
                            if '{{%s}}'%var in value2:
                                value2 = value2.replace('{{%s}}'%var, str(var_dcit[var]))
                        path = value2
                    #body 替换变量
                    elif key2 == 'body':
                        for var in varname_list:
                            if '{{%s}}'%var in value2:
                                value2 = value2.replace('{{%s}}'%var, str(var_dcit[var]))
                        #转义
                        if '\'' in value2:
                            value2 = value2.replace('\'', '\\\'')
                        body = value2
                    elif key2 == 'headers':
                        headers = value2
                expression = value1['expression']
                #expression = value1['expression']
                #替换连接符
                if '&&' in expression:
                    expression = expression.replace('&&', 'and')
                if '||' in expression:
                    expression = expression.replace('||', 'or')
                for var in varname_list:
                    #表达式变量替换
                    if var in expression:
                        #if isinstance(var_dcit[var], str):
                        if isinstance(var_dcit[var], int):
                            expression = expression.replace(var, str(var_dcit[var]))
                        else:
                            expression = expression.replace(var, '\''+var_dcit[var]+'\'')
                        #else:
                            #expression = expression.replace(var, var_dcit[var])
                expression_dcit.update({key1:expression})
                #前置处理
                #temp_request_template = temp_request_template.lstrip('\n')
                #替换请求次数
                #if key1:
                #    temp_request_template = temp_request_template.replace('{rnum}', key1)
                #else:
                #    temp_request_template = temp_request_template.replace('{rnum}', 'r0')
                #替换路径
                if path:
                    temp_request_template = temp_request_template.replace('{path}', path)
                else:
                    temp_request_template = temp_request_template.replace('{path}', '/')
                #替换方法
                if method:
                    temp_request_template = temp_request_template.replace('{method}', method)
                else:
                    temp_request_template = temp_request_template.replace('{method}', 'get')
                #替换数据
                if body:
                    temp_request_template = temp_request_template.replace('{body}', body)
                else:
                    temp_request_template = temp_request_template.replace('{body}', '')
                #替换头部
                if headers:
                    temp_request_template = temp_request_template.replace('{header}', str(headers))
                else:
                    temp_request_template = temp_request_template.replace('{header}', '{}')
                    
                #temp_request_template = http请求
                temp = temp + temp_request_template
        
            #判断请求间的逻辑关系
            logic_expression = yamldict.get('expression', None)
            if logic_expression:
                #替换连接符
                if '&&' in logic_expression:
                    logic_expression = logic_expression.replace('&&', 'and')
                if '||' in logic_expression:
                    logic_expression = logic_expression.replace('||', 'or')
                if '()' in logic_expression:
                    logic_expression = logic_expression.replace('()', '')
                
                for key, value in expression_dcit.items():
                    if key in logic_expression:
                        logic_expression = logic_expression.replace(key, value)
            #填充http请求
            yaml_template = yaml_template.replace('{requests}', temp)
            #填充判断逻辑
            yaml_template = yaml_template.replace('{expression}', logic_expression)
        self.text.delete('1.0','end')
        self.text.insert(INSERT, yaml_template)
        
    def hide(self):
        """
        隐藏界面
        """
        self.yaml.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.yaml.update()
        self.yaml.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        try:
            self.Creat_from_yaml_xray()
        except Exception as e:
            messagebox.showerror(title='错误', message=e)
        finally:
            self.yaml.destroy()
