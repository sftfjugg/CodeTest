from urllib.parse import quote,unquote
import random
import base64 as bs64
import time
import mmh3
import codecs
import re

#随机字符
def randomLowercase(index) -> str:
    ascii = 'abcdefghijklmnopqrstuvwxyz'
    i = ''
    for index in range(index):
        i += random.choice(ascii)
    return i
#随机数字
def randomInt(j,k) -> int:
    return random.randrange(j,k)

#base64加密
def base64(j) -> str:
    if isinstance(j, str):
        return bs64.b64encode(j.encode('utf8',errors="ignore")).decode()
    else:
        return bs64.b64encode(j).decode()
#base64解密
def base64Decode(j) -> str:
    if isinstance(j, str):
        return bs64.b64decode(j).decode()
    else:
        return bs64.b64decode(j.decode()).decode()
#url编码
def urlencode(j):
    return quote(j)
#url解码
def urldecode(j):
    if isinstance(j, str):
        return unquote(j)
    else:
        return unquote(j.decode())
#faviconHash编码
def faviconHash(url):
    return mmh3.hash(codecs.lookup('base64').encode(url))

#md5编码
def md5(j) -> str:
    from hashlib import md5
    return md5(j.encode('utf8',errors="ignore")).hexdigest()

def bytes(j) -> bytes:
    return j.encode('utf8',errors="ignore")

def substr(i, j ,k) -> str:
    try:
        return i[j:j+k]
    except:
        return ''

def replaceAll(i, j ,k) -> str:
    try:
        return i.replace(j,k)
    except:
        return ''

def sleep(i):
    time.sleep(i)
    
def string(i):
    return str(i)
    
if __name__ == '__main__':
    a = 'urlencode(base64("`echo " + "123" + " > " + "pei.txt" + "`"))'
    print(eval(a))
    #print(urldecode(b'%23'))
    