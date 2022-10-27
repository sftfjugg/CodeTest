# -*- coding: utf-8 -*-
from ThreatInfo.util.six import withMetaclass
from ThreatInfo.util.singleton import Singleton
from ThreatInfo.WebRequest import WebRequest
from ClassCongregation import Logger
import util.globalvar as GlobalVar
import dns.resolver
import urllib3
import time
import sys
import re
#去除错误警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'
    }
TIMEOUT = 5

class InfoCollect(withMetaclass(Singleton)):
    domain2ip_Collect = []
    ip2domain_Collect = []
    
    ipWhois_Collect = []
    domainWhois_Collect = []
    beianWhois_Collect = []
    threatbook_Collect = []
    aiqicha_Collect = []

    @classmethod
    def addDomain2ip_Collect(cls, func):
        cls.domain2ip_Collect.append(func)
        return func

    @classmethod
    def addIp2domain_Collect(cls, func):
        cls.ip2domain_Collect.append(func)
        return func

    @classmethod
    def addIpWhois_Collect(cls, func):
        cls.ipWhois_Collect.append(func)
        return func

    @classmethod
    def addDomainWhois_Collect(cls, func):
        cls.domainWhois_Collect.append(func)
        return func

    @classmethod
    def addBeianWhois_Collect(cls, func):
        cls.beianWhois_Collect.append(func)
        return func

    @classmethod
    def addThreatbook_Collect(cls, func):
        cls.threatbook_Collect.append(func)
        return func

    @classmethod
    def addAiqicha_Collect(cls, func):
        cls.aiqicha_Collect.append(func)
        return func

@InfoCollect.addDomain2ip_Collect
def query_A_ip138(domain):
    """ 域名A记录 """
    url = 'https://site.ip138.com/domain/read.do?domain={}&time=1665221398364'.format(domain)
    try:
        resp_data = WebRequest().get(url=url, headers=headers, timeout=TIMEOUT).json
        data_list = resp_data.get('data', [])
        if len(data_list) == 1:
            ip = data_list[0].get('ip','')
            return ip
        return 'CDN'
        # li_list = tree.xpath('.//div[@id=\'J_ip_history\']/p')
        # ip = li_list[0].xpath('./a/text()')[0]
    except Exception as error:
        Logger.error('域名A记录-query_A_ip138: '+ str(error))
        return 'Error'

@InfoCollect.addDomain2ip_Collect
def query_A(domain):
    """ 域名A记录 """
    try:
        dns_A_ips = dns.resolver.query(domain, "A")
        ips = []
        for each_ip in dns_A_ips:
            each_ip = str(each_ip)
            if re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$').match(each_ip):    # 正则匹配是否是IP
                ips.append(str(each_ip))
        return ','.join(ips) if len(ips) !=0 else ''
    except Exception as error:
        Logger.error('域名A记录-query_A: '+ str(error))
        return 'Error'

@InfoCollect.addIp2domain_Collect
def ip2domain_ip138(ip):
    """ ip反查域名 """
    domains = []
    url = 'https://site.ip138.com/{}'.format(ip)
    try:
        tree = WebRequest().get(url=url, headers=headers, timeout=TIMEOUT).tree
        li_list = tree.xpath('.//ul[@id=\'list\']//li')
        for tr in li_list[2:]:
            # Time = tr.xpath('./span/text()')[0]
            domain = tr.xpath('./a/text()')[0]
            domains.append(domain)
        return ','.join(domains) if len(domains) !=0 else 'None'
    except Exception as error:
        Logger.error('ip反查域名-ip2domain_ip138: '+ str(error))
        return 'Error'

@InfoCollect.addIp2domain_Collect
def ip2domain(ip):
    """ ip反查域名 """
    url = 'http://api.webscan.cc/?action=query&ip={}'.format(ip)
    try:
        res = WebRequest().get(url=url, headers=headers, timeout=TIMEOUT)
        text = res.text
        if text == '':return 'None'
        if text == 'null':return 'None'
        if text != 'null':
            results = eval(text)
            domains = []
            for each in results:
                domains.append(each['domain'])
            return ','.join(domains) if len(domains) !=0 else 'None'
    except Exception as error:
        Logger.error('ip反查域名-ip2domain: '+ str(error))
        return 'Error'

@InfoCollect.addIp2domain_Collect
def ip2domain_ssl_CN(ip):
    """ 通过返回SSL证书的CN实现ip反查域名 """
    from requests.packages.urllib3.contrib import pyopenssl as reqs
    import socket
    #设置get_server_certificate超时时间
    socket.setdefaulttimeout(TIMEOUT)
    port='443'
    try:
        x509 = reqs.OpenSSL.crypto.load_certificate(
            reqs.OpenSSL.crypto.FILETYPE_PEM,
            reqs.ssl.get_server_certificate((ip, port))
        )
        domain = x509.get_subject().CN
        return str(domain) if domain else 'None'
    except Exception as error:
        Logger.error('通过返回SSL证书的CN实现ip反查域名-ip2domain_ssl_CN: '+ str(error))
        return 'Error'
    
# @InfoCollect.addIpaddress_Collect
# def get_ip_address(ip):
#     """ 查询ip归属地 """
#     url = r'http://whois.pconline.com.cn/ipJson.jsp?ip={}&json=true'.format(ip)
#     try:
#         res = WebRequest().get(url=url, headers=headers, timeout=TIMEOUT, verify=False)
#         text = res.text
#         json_text = json.loads(text)
#         address = json_text['addr'].strip(' ')
#         return address if address else 'None'
#     except Exception:
#         return 'Error'
    
# @InfoCollect.addSpace_Collect
# def QuakeApi(ip):
#     """ 360QuakeApi """
#     url = f'https://quake.360.cn/api/v3/search/quake_service'
#     api_key = cf.get('quake api', 'X-QuakeToken')
#     headers = {
#         "X-QuakeToken": api_key,
#         "Content-Type": "application/json",
#     }
#     data = {
#         'query': 'ip="%s" AND service: "http/ssl"'%ip,
#         'start': 0,
#         'size': 10,
#         "ignore_cache": False,
#     }
#     res = WebRequest().post(url=url, headers=headers, json=data)
#     print(res.json())
    
@InfoCollect.addBeianWhois_Collect
def Beian(domain):
    """ 站长之家备案查询 """
    url = "https://micp.chinaz.com/?query={}".format(domain)
    try:
        res = WebRequest().get(url=url, headers=headers, allow_redirects=False, timeout=TIMEOUT)
        if '当前域名未备案或者备案取消' in res.text:
            return 'None'
        beianName = re.search('<tr><td class="ww-3 c-39 bg-3fa">主办单位：</td><td class="z-tl">(.*)</td></tr>', res.text).group(1)
        beianType = re.search('<tr><td class="ww-3 c-39 bg-3fa">单位性质：</td><td class="z-tl">(.*)</td></tr>', res.text).group(1)
        beianNum = re.search('<tr><td class="ww-3 c-39 bg-3fa">备案号：</td><td class="z-tl">(.*)</td></tr>', res.text).group(1)
        return {
            "beianName": beianName,
            "beianType": beianType,
            "beianNum": beianNum,
        }
    except Exception as error:
        Logger.error('站长之家备案查询-Beian: '+ str(error))
        return 'Error'

@InfoCollect.addDomainWhois_Collect
def domainWhois(domain):
    """ 站长之家域名whois """
    key = GlobalVar.get_value('CHINAZ_DOMAIN_API_KEY')
    url = "https://apidatav2.chinaz.com/single/whois?key={}&domain={}".format(key,domain)
    try:
        resp_data = WebRequest().get(url=url, headers=headers, allow_redirects=False, timeout=TIMEOUT).json
        whoisdata = resp_data.get('Result')
        return whoisdata
    except Exception as error:
        Logger.error('站长之家域名whois-domainWhois: '+ str(error))
        return 'Error'

@InfoCollect.addIpWhois_Collect
def ipWhois(ip):
    """ 站长之家ipwhois """
    key = GlobalVar.get_value('CHINAZ_IP_API_KEY')
    url = "https://apidatav2.chinaz.com/single/ip?key={}&ip={}".format(key,ip)
    try:
        resp_data = WebRequest().get(url=url, headers=headers, allow_redirects=False, timeout=TIMEOUT).json
        ipWhoisdata = resp_data.get('Result')
        return ipWhoisdata
    except Exception as error:
        Logger.error('站长之家ipwhois-ipWhois: '+ str(error))
        return 'Error'

@InfoCollect.addThreatbook_Collect
def threatbookinfo(ip):
    """ 微步威胁分析 """
    key = GlobalVar.get_value('THREATBOOK_API')
    url = "https://api.threatbook.cn/v3/scene/ip_reputation"
    query = {
        "apikey": key,
        "resource": "%s" % ip,
        "lang":"zh"
    }
    try:
        resp_data = WebRequest().post(url=url, headers=headers, data=query, allow_redirects=False, timeout=TIMEOUT).json
        if resp_data.get('response_code') == 0:
            # 微步标签
            judgments = resp_data.get('data')['%s' % ip]['judgments']
            # 标签类别
            tags_classes = resp_data.get('data')['%s' % ip]['tags_classes'][0]['tags']
            # 场景
            scene = resp_data.get('data')['%s' % ip]['scene']
            if resp_data.get('data')['%s' % ip]['is_malicious'] == False:
                is_malicious = '否'
            else:
                is_malicious = '是'
            return {
                'judgments': judgments,
                'tags_classes': tags_classes,
                'scene': scene,
                'is_malicious' : is_malicious,
            }
        return 'Error'
    except Exception as error:
        Logger.error('微步威胁分析-threatbookinfo: '+ str(error))
        return 'Error'

# @InfoCollect.addIpWhois_Collect
# def ipWhois_taobao(ip):
#     """ 淘宝ipwhois """
#     url = "https://ip.taobao.com/ipSearch?ipAddr={}".format(ip)
#     key_list = []
#     value_list = []
#     try:
#         tree = WebRequest().get(url=url, headers=headers, allow_redirects=False, timeout=TIMEOUT).tree
#         th_list = tree.xpath('.//table[@id=\'ip_all\']//tbody//tr[1]//th')
#         td_list = tree.xpath('.//table[@id=\'ip_all\']//tbody//tr[2]//td')
#         for th in th_list:
#             key = th.xpath('./text()')[0]
#             key_list.append(key)
#         value_list.append(td_list[0].xpath('./span/text()')[0])
#         for td in td_list[1:]:
#             value = td.xpath('./text()')[0]
#             value_list.append(value)
#         return dict(zip(key_list,value_list))
#     except Exception as e:
#         return 'Error'

# @InfoCollect.addAiqicha_Collect
# def aiqicha(beianName):
#     """ 爱企查 """
#     # 获取匹配度最高的pid
#     url = 'https://aiqicha.baidu.com/index/suggest'
#     data = {"q": beianName}
#     headers1 = {
#             'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
#             'sec-ch-ua-mobile': '?0',
#             'Upgrade-Insecure-Requests': '1',
#             'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
#             'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
#             'Cookie': 'BDPPN=b355f0dd5e3595723bd0bfe53b09c873;BDUSS=UxSkRCdFlrfmg0ZFg2ZkVJelcyVWpJMm12cjU4WXB1UnBLemRmbEZYcFdqVTFoSVFBQUFBJCQAAAAAAAAAAAEAAAClOWAGeHV0YW8yMDEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFYAJmFWACZhbz;BIDUPSID=1FAA6F4D89C6311BCA477B5B766A408D; PSTM=1618319039; BAIDUID=1FAA6F4D89C6311BB29AB4FE1AEC0084:FG=1; delPer=0; PSINO=1; __yjs_duid=1_b459443288e79c76f299132c456ba4bf1630477596321; H_PS_PSSID=34437_34443_34379_34496_31254_34004_34092_34106_26350_34418_22159; Hm_lvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630490457; ZX_UNIQ_UID=235603df155283fc03e1ca707604f293; _j47_ka8_=57; log_guid=de290298a47b69cc93fdb016cc66a223; BA_HECTOR=8ha10h258l242k20rp1gj0bse0r; Hm_lpvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630547983; _fb537_=xlTM-TogKuTwvJ4X5I46%2AIuoCngLaKAfi6M%2AOS5mhcHqmd; __yjs_st=2_OTg5ZGJiYzBlZThjNWEyZTU0ZTA1NmVhNGRjZGI3NWNmMzRhYmY1YTNhODUxNzQ0OTlmMmQ2NmYzNWEwNzY3N2MzY2U5MzJkZjJhMjljYjE4MWJjZTYxMDk0YzZhZTlmZThjMzFiODJmNDUwNzU5YjBjY2Q3Y2Y4NTk4OGQ1MjkzNzI2YTAxM2FlZGVlNTY2MzY4ZTdmMmI2MmNjYzQ2YTkzYjdkODc0ZGU4YTcyZTNlYzNkMDEwZGE2ZDFmZWVhMDc5ZjgxMjJhMzIzODVmMzFhNWRlMzA2Y2M0Mjc5ZDQxY2UyMjc2ODFlMjM3MzRkYjFiMjI4OTNhYTI5YTkxM183X2RlNTJjNTZi; ab_sr=1.0.1_MWE0MzIwZjE0ZjQ2OTIzYTk5ZGMyOTQ1ZTBkYzcwM2MwOGI0ZWRjZjFmMmMxZDM0Y2Q0MzNlNzM2OWFiZmY5Y2YxM2MyOTM1ODJkZWExNDE0YzU3MmM3ODY2MzI4YWJhZWYxODBjZWJlYjhhM2FjNmE2MThjYmU0MmJiNWFhYjQ5NTEyMTE5ODA0OGQ4MGEyYTRiNDA3YTk2MjI3M2YwOQ==; _s53_d91_=2a32a31ab347483e2096871f98f0842b6ea08522c97c28c46353e56e86219e6409e838e83117a08774a8da295a5e9b0ed642b4685b780d1731e601956b4f0b82cbd45570696a8e96493db3197f88b7dd82945497dac07440c6e49d09f3e22f1452a5c00539afa2e4128ef497a792655c5b94fd56f8950542cf4f975e7426d5e73f199201a826c95d393e4afb78b199329d6e9fd6fcb87ed85a8e1e769c9ee4ff176e1f2f50250e3a86706cc09695d4d362f6ce2bba20a8c7fd13308cd1ea48f061c48546de8fa42c1ab0e9faf387a0c4; _y18_s21_=70c80ef2; RT="z=1&dm=baidu.com&si=te7c3g5s27i&ss=kt2a2egs&sl=4&tt=1d8h&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf&ld=3wfa&ul=1qdpt"'
#         }
#     try:
#         res = WebRequest().post(url=url, data=data, headers=headers1, timeout=TIMEOUT)
#     except Exception as e:
#         return 'Error'
    
#     text = res.text
#     # 取第一个pid，是匹配度最高的
#     pids = re.findall('pid":"(.*?)"', text)
#     if pids == []:
#         #没有匹配到pids
#         return 'None'
#     pid = pids[0]
    
#     # 获取基本信息:公司名、邮箱地址、联系方式
#     companyDetail_infos = {"emails": "", "telephone": ""}
#     try:
#         url = "https://aiqicha.baidu.com/company_detail_{}".format(pid)
#         res = WebRequest().get(url=url, headers=headers1, timeout=TIMEOUT)
#         text = res.text
#         # print(text)
#         # companyName = re.findall('entName":"(.*?)"', text)[0].encode('utf-8').decode('unicode_escape')
#         emails = re.findall(r'email":"(.*?)"', text)
#         telephone = re.findall('telephone":"(.*?)"', text)
#         # print("公司名、邮箱地址、联系方式")
#         # print(companyName[0].encode('utf-8').decode('unicode_escape'), emails, telephone)
#         companyDetail_infos = {"emails": emails, "telephone": telephone}
#     except Exception as e:
#         # print(e.args)
#         pass
    
#     # 获取网站备案、对外投资、控股企业、分支机构
#     headers2 = {
#         'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
#         'Accept': 'application/json, text/plain, */*',
#         'X-Requested-With': 'XMLHttpRequest',
#         'sec-ch-ua-mobile': '?0',
#         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
#         'Sec-Fetch-Site': 'same-origin',
#         'Sec-Fetch-Mode': 'cors',
#         'Sec-Fetch-Dest': 'empty',
#         'Accept-Language': 'zh-CN,zh;q=0.9',
#         'Referer': 'https://aiqicha.baidu.com/company_detail_{}'.format(pid),
#         'Zx-Open-Url': 'https://aiqicha.baidu.com/company_detail_{}'.format(pid),
#         'Cookie': 'BIDUPSID=1FAA6F4D89C6311BCA477B5B766A408D; PSTM=1618319039; BAIDUID=1FAA6F4D89C6311BB29AB4FE1AEC0084:FG=1; delPer=0; PSINO=1; __yjs_duid=1_b459443288e79c76f299132c456ba4bf1630477596321; H_PS_PSSID=34437_34443_34379_34496_31254_34004_34092_34106_26350_34418_22159; Hm_lvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630490457; ZX_UNIQ_UID=235603df155283fc03e1ca707604f293; _j47_ka8_=57; log_guid=de290298a47b69cc93fdb016cc66a223; BA_HECTOR=8ha10h258l242k20rp1gj0bse0r; _s53_d91_=8a7993934c2e3aed3016469d17b932073b7b54a406de44d238e6f350d1dff19c6f4ed0cfe8dd8c73157858ec8bdf74ba70569f6014536cdd9897cbc334d0e4a457dc349592e0866ba802c2e55593df16336a09ec583cbc66c871f2a6cdd57bd252b99c7aac7dfa060e1c280a3f44131b41af584d3541e986e1f842e0a94548c08ef935673ef819b1c36bbe2257c9472c01275ae97e3a8831197fae58c859da19d779c76a4d48dcf0ac69a2e01c9983c920535b992646bb7eca4508e2aace1c9d602f8a87f140cf8a150259da45b437df; _y18_s21_=7e1a75d9; RT="z=1&dm=baidu.com&si=te7c3g5s27i&ss=kt2a2egs&sl=2&tt=wzf&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf"; Hm_lpvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630547983; ab_sr=1.0.1_YzE2ZGZiZTgzNGM4OGJlYjMxOThlMWFhZjgzNGI2MzU0ZDkwY2UyYjQzMzA2YjViYTYxMmM4ODViZTVhZmY4MmVhNDZkNmRjNjY3YmQ0ZGNkYjc4Y2E5ZjEzYzc4NmZmNWJjNmFiYWViOTU1YzNmY2UzNjM4MzBkM2ViMTY2YjJmZWM3NGVmNjYwNDMyYzExN2E0NWFhMjAzZGNlYzIxMA==; _fb537_=xlTM-TogKuTwvJ4X5I46%2AIuoCngLaKAfi6M%2AOS5mhcHqmd; __yjs_st=2_OTg5ZGJiYzBlZThjNWEyZTU0ZTA1NmVhNGRjZGI3NWNmMzRhYmY1YTNhODUxNzQ0OTlmMmQ2NmYzNWEwNzY3N2MzY2U5MzJkZjJhMjljYjE4MWJjZTYxMDk0YzZhZTlmZThjMzFiODJmNDUwNzU5YjBjY2Q3Y2Y4NTk4OGQ1MjkzNzI2YTAxM2FlZGVlNTY2MzY4ZTdmMmI2MmNjYzQ2YTkzYjdkODc0ZGU4YTcyZTNlYzNkMDEwZGE2ZDFmZWVhMDc5ZjgxMjJhMzIzODVmMzFhNWRlMzA2Y2M0Mjc5ZDQxY2UyMjc2ODFlMjM3MzRkYjFiMjI4OTNhYTI5YTkxM183X2RlNTJjNTZi'
#     }
    
#     url = r"https://aiqicha.baidu.com/compdata/navigationListAjax?pid={}".format(pid)
#     # print(url)
#     res = WebRequest().get(url=url, headers=headers2, timeout=TIMEOUT)
#     text = res.text
#     text = text.encode('utf-8').decode('unicode_escape')
#     # print(text)
#     text_json = json.loads(text)
#     basic, certRecord = [], []
#     for _ in text_json["data"]:
#         if _["id"] == "basic":
#             # 基本信息
#             basic = _["children"]
#         if _["id"] == "certRecord":
#             # 知识产权
#             certRecord = _["children"]
    
#     # 网站备案
#     for each in certRecord:
#         if each["name"] == "网站备案":
#             webRecord_num = each["total"]

#     # 页数
#     icpinfo_page = webRecord_num // 10 + 1
    
#     # 网站备案信息
#     icpinfo_infos = []
#     for i in range(1, icpinfo_page+1):
#         try:
#             invest_url = "https://aiqicha.baidu.com/detail/icpinfoajax?p={}&size={}&pid={}".format(i, 10, pid)
#             res = WebRequest().get(url=invest_url, headers=headers2, timeout=TIMEOUT)
#             text = res.text.encode('utf8').decode('unicode_escape')
#             text = json.loads(text)
#             data = text["data"]
#             # print(data)
#             # print("名称、备案域名、备案号")
#             for each in data["list"]:
#                 siteName = each["siteName"]
#                 # print("收集网站【{}】的备案信息".format(siteName))
#                 domain = each["domain"]
#                 icpNo = each["icpNo"]
#                 # print(siteName, domain, icpNo)
#                 icpinfo_infos.append({"siteName": siteName, "domain": domain, "icpNo": icpNo})
#         except Exception as e:
#             # print(e.args)
#             pass
#     icpinfo_infos.append(companyDetail_infos)
#     return icpinfo_infos

if __name__ == '__main__':
    print('123')