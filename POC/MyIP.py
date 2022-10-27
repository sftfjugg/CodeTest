import requests

requests.packages.urllib3.disable_warnings()
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
    'Accept': '*/*',
    'Connection': 'keep-alive',
    'Accept-Language': 'zh-CN,zh;q=0.8'
}

def check(**kwargs):
    url = 'http://myip.ipip.net/'
    url2 = 'http://httpbin.org/ip'
    url3 = 'https://httpbin.org/ip'
    response = requests.get(url3, headers=headers, timeout=10, verify=False)
    print(response.text)