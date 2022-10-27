from ajpy.ajp import AjpForwardRequest
from urllib.parse import quote,unquote
from urllib import parse
import random
import base64 as bs64
import time
import mmh3
import codecs
import re
import socket
import sys
import datetime

#判断是否是IP地址
def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False

#颜色输出函数
def print_error(error):
    #自动添加\n换行符号,方便自动换行
    now = datetime.datetime.now()
    # sys.stderr.write("["+str(now)[11:19]+"] " +'[#type] '+str(type(error))+' [#message] '+str(error) + end)
    sys.stderr.write("["+str(now)[11:19]+"] "+str(error).strip()+'\n')

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

def parse_url(url):
    if re.search(r'^\d+\.\d+\.\d+\.\d+$', url):
        return url
    # 判断给出的url是www.baiud.com还是www.baidu.com/path这种形式
    try:
        if parse.urlparse(url).scheme:
            url = parse.urlparse(url).netloc
            if ':' in url:
                url = re.sub(r':\d+', '', url)
            url = socket.gethostbyname(url)
        elif ':' in url:
            url = re.sub(r':\d+', '', url)
            url = socket.gethostbyname(url)
        else:
            url = ''
        return url
    except Exception as error:
        print_error(error)
        return ''

    # Apache Tomcat CVE-2020-1938 "AJP" protocol check def
def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
    fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
    fr.method = method
    fr.protocol = "HTTP/1.1"
    fr.req_uri = req_uri
    fr.remote_addr = target_host
    fr.remote_host = None
    fr.server_name = target_host
    fr.server_port = 80
    fr.request_headers = {
        'SC_REQ_ACCEPT': 'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp,*/*;q=0.8',
        'SC_REQ_CONNECTION': 'keep-alive',
        'SC_REQ_CONTENT_LENGTH': '0',
        'SC_REQ_HOST': target_host,
        'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'en-US, en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    fr.is_ssl = False
    fr.attributes = []
    return fr

def ftp_login(hosts):
    import ftplib
    try:
        ip, port, username, password, timeout = hosts.split(':')
        ftp = ftplib.FTP(
            host=ip,
            user=username,
            passwd=password,
            timeout=int(timeout),
        )
        ftp.quit()
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

def ssh_login(hosts):
    import paramiko
    try:
        ip, port, username, password, timeout = hosts.split(':')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=ip,
            port=int(port), 
            username=username, 
            password=password,
            timeout=int(timeout),
            # 关闭 否则会报 "No existing session"
            allow_agent=False,
            look_for_keys=False,
        )
        #ssh.close()
        stdin, stdout, stderr = ssh.exec_command('df')
        result = stdout.read()
        ssh.close()
        if result:
            return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

def telnet_login(hosts):
    import telnetlib
    try:
        ip, port, username, password, timeout = hosts.split(':')
        telnet = telnetlib.Telnet(ip, timeout=int(timeout))
        telnet.set_debuglevel(2)
        telnet.read_until("\n")
        telnet.write(username.encode('ascii') + "\r\n".encode('ascii'))
        telnet.read_until("\n")
        telnet.write(password.encode('ascii') + "\r\n".encode('ascii'))
        telnet.read_all()
        telnet.close()
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))
        
def mssql_login(hosts):
    import pymssql
    try:
        ip, port, username, password, timeout = hosts.split(':')
        mssql = pymssql.connect(
            host=ip, 
            user=username, 
            password=password, 
            database='master',
            port=int(port),
            charset='utf8',
            login_timeout=int(timeout)
        )
        mssql.close()
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

def oracle_login(hosts):
    import cx_Oracle
    try:
        ip, port, username, password, timeout = hosts.split(':')
        # 构建数据源
        dsn = cx_Oracle.makedsn(ip, int(port), 'orcl')
        # 创建连接
        # oracle = cx_Oracle.connect(username, password, '{}:{}/{}'.format(ip, port, 'orcl'))
        oracle = cx_Oracle.connect(username, password, dsn, callTimeout=int(timeout))
        oracle.close()
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

def mysql_login(hosts):
    import pymysql
    try:
        ip, port, username, password, timeout = hosts.split(':')
        mysql = pymysql.connect(
            host=ip, 
            user=username, 
            password=password, 
            db='information_schema',
            port=int(port), 
            charset='utf8',
            read_timeout=int(timeout),
            write_timeout=int(timeout),
        )
        mysql.close()
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

def postgresql_login(hosts):
    import psycopg2
    try:
        ip, port, username, password, timeout = hosts.split(':')
        postgresql = psycopg2.connect(
            host=ip, 
            port=int(port), 
            user=username, 
            password=password,
            connect_timeout=int(timeout)
        )
        postgresql.close()
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

def rdp_login(hosts):
    import subprocess
    try:
        ip, port, username, password, timeout = hosts.split(':')
        cmd = ['wfreerdp', '/v:%s:%d' % (ip, int(port)), '/u:%s' % username, '/p:%s' % password, '/cert-ignore', '+auth-only', '/sec:nla', '/log-level:error']
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        # m = re.search(' (ERR.+?) ', err)
        # print(out)
        # print(err)
        return True
    except Exception as error:
        print_error(error)
        return False
    finally:
        time.sleep(randomInt(0,1))

if __name__ == '__main__':
    # import socket
    # import socks
    # socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1008)
    # socket.socket = socks.socksocket
    # b = re.search('POstgresql', "postgresql_login")
    # print(b)
    a = mysql_login('127.0.0.1:3306:root:root:2')
    print(a)
    # print_error("123")
    