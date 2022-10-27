# -*- coding: UTF-8 -*-
#Author:R3start
#这是一个用于IP和域名碰撞匹配访问的小工具
import requests
import re

ipstr = """
103.188.120.174
103.188.120.173
103.188.120.244
103.188.120.172
103.188.120.80
103.188.120.65
103.188.120.241
"""

hoststr = """
11666x.com
www.616105.com
"""

iplist = ipstr.split('\n')[1:-1]
hostlist = hoststr.split('\n')[1:-1]

def check(**kwargs):
    print("====================================匹 配 成 功====================================")
    #读取IP地址
    for ip in iplist:
        http_s = ['http://','https://']
        for h in http_s :
            #读取host地址
            for host in hostlist:
                headers = {
                    'Host':host,
                    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
                    }
                try:
                    r = requests.session()
                    requests.packages.urllib3.disable_warnings()
                    rhost = r.get(h + ip, verify=False, headers=headers, timeout=5)
                    rhost.encoding='utf-8'
                    #获取标题
                    title = re.search('<title>(.*)</title>', rhost.text).group(1)
                    print('%s -- %s 协议：%s 数据包大小：%d 标题：%s' % (ip,host,h,len(rhost.text),title))
                except Exception:
                    error = ip + " --- " + host + " --- 访问失败！~"
                    print(error)

if __name__ == '__main__':
    iplist.remove('')
    print(iplist)