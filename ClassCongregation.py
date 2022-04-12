import random,requests,time,binascii,subprocess,re,sys,os,webbrowser
import xml.etree.ElementTree as ET
import tkinter as tk
import base64
import threading
import json

from tkinter import END,ttk
from urllib.parse import urlparse
from Crypto.Cipher import DES
from urllib import request
from lxml import etree

#logging.basicConfig(level=logging.INFO,  
#            format='%(asctime)s %(message)s',
#            datefmt='%Y-%m-%d  %H:%M:%S %a ',
#            filename='./log/info.txt',
#            filemode='a')
#Dnslog判断
class Dnslog:
    def __init__(self):
        self.header = {
		'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36',
		'Connection':'close',
        }
        try:
            self.host = self.get_dnslog_url()
        except Exception as e:
            print(e)
            self.host=""

    def dns_host(self) -> str:
        return str(self.host)

    def get_dnslog_url(self):
        try:
            rep = requests.get('http://dnslog.cn/getdomain.php', headers=self.header, timeout=15)
            self.cookie = re.search('=(.*);', rep.headers['Set-Cookie'])
            self.dnslog_cn = rep.text  #获取测试域名
            return self.dnslog_cn
        except Exception as e:
            print("[-]获取DOSLOG域名出错%s"%e)

    def result(self) -> bool:
        return self.dnslog_cn_dns()

    def dnslog_cn_dns(self) -> bool:
        time.sleep(0.5)
        try:
            status = requests.get('http://dnslog.cn/getrecords.php', cookies={'PHPSESSID': self.cookie.group(1)} ,headers=self.header, timeout=15)
            self.dnslog_cn_text = status.text
            if self.dnslog_cn_text.find('dnslog') != -1:  # 如果找到Key
                return True
            else:
                return False
        except Exception as e:
            print("[-]寻找%s请求记录时出错"%self.dnslog_cn, e)

    def dns_text(self):
        return self.dnslog_cn_text


class Ceye(object):
    def __init__(self, username=None, password=None, token="794851b9e8df2d3964cde6d0786a2f2d"):
        self.headers = {'User-Agent': 'curl/7.80.0'}
        self.token = token
        self.username = username
        self.password = password
        self.check_account()

    #验证token是否有效
    def token_is_available(self):
        if self.token:
            # distinguish Jwt Token & API Token
            self.headers['Authorization'] = self.token if len(self.token) < 48 else f'JWT {self.token}'
            try:
                resp = requests.get('http://api.ceye.io/v1/identify', headers=self.headers)
                if resp and resp.status_code == 200 and "identify" in resp.text:
                    return True
                else:
                    print(resp.text)
            except Exception as ex:
                print(str(ex))
        return False

    #使用用户名和密码换取token
    def new_token(self):
        data = '{{"username": "{}", "password": "{}"}}'.format(self.username, self.password)
        try:
            resp = requests.post('https://api.zoomeye.org/user/login', data=data)
            if resp.status_code != 401 and "access_token" in resp.text:
                content = resp.json()
                self.token = content['access_token']
                self.headers['Authorization'] = f'JWT {self.token}'
                return True
            else:
                print(resp.text)
        except Exception as ex:
            print(str(ex))
        return False

    #检测账号是否登录, 否则使用用户名、密码申请token
    def check_account(self):
        if self.token_is_available():
            return True
        elif self.username and self.password:
            if self.new_token():
                return True
            else:
                print("[-]The username or password is incorrect")

    def verify_request(self, flag, type="request"):
        """
        Check whether the ceye interface has data
        :param flag: Input flag
        :param type: Request type (dns|request), the default is request
        :return: Boolean
        """
        ret_val = False
        counts = 3
        url = (
            "http://api.ceye.io/v1/records?token={token}&type={type}&filter={flag}"
        ).format(token=self.token, type=type, flag=flag)
        while counts:
            try:
                time.sleep(1)
                resp = requests.get(url)
                if resp and resp.status_code == 200 and flag in resp.text:
                    ret_val = True
                    break
            except Exception as ex:
                print(ex)
                time.sleep(1)
            counts -= 1
        return ret_val

    def exact_request(self, flag, type="request"):
        """
        Obtain relevant data by accessing the ceye interface
        :param flag: Input flag
        :param type: Request type (dns|request), the default is request
        :return: Return the acquired data
        """
        counts = 3
        url = (
            "http://api.ceye.io/v1/records?token={token}&type={type}&filter={flag}"
        ).format(token=self.token, type=type, flag=flag)
        while counts:
            try:
                time.sleep(1)
                resp = requests.get(url)
                if resp and resp.status_code == 200 and flag in resp.text:
                    data = json.loads(resp.text)
                    for item in data["data"]:
                        name = item.get("name", '')
                        pro = flag
                        suffix = flag
                        t = get_middle_text(name, pro, suffix, 0)
                        if t:
                            return t
                    break
            except Exception as ex:
                print(ex)
                time.sleep(1)
            counts -= 1
        return False

    def build_request(self, value, type="request"):
        """
        Generate the sent string
        :param value: Enter the message to be sent
        :param type: Request type (dns|request), the default is request
        :return: dict { url: Return the received domain name,flag: Return a random flag }
        Example:
          {
            'url': 'http://htCb.jwm77k.ceye.io/htCbpingaaahtCb',
            'flag': 'htCb'
          }
        """
        ranstr = random_name(4)
        domain = self.getsubdomain()
        url = ""
        if type == "request":
            url = "http://{}.{}/{}{}{}".format(ranstr, domain, ranstr, value, ranstr)
        elif type == "dns":
            url = "{}{}{}.{}".format(ranstr, re.sub("\W", "", value), ranstr, domain)
        return {"url": url, "flag": ranstr}

    def getsubdomain(self):
        """
        Obtain subdomains through ceye token
        :return: Return the obtained domain name
        """
        r = requests.get("http://api.ceye.io/v1/identify", headers=self.headers).json()
        suffix = ".ceye.io"
        try:
            indetify = r["data"]["identify"]
        except KeyError:
            return None
        return indetify + suffix
    
    #dns_callback
    def dns_host(self) -> str:
        self.value = random_name(6)
        self.flag = self.build_request(self.value, type='dns')
        domain = self.flag["url"]
        return domain
    
    #result
    def result(self) -> bool:
        return self.ceye_cn_dns()
    
    def ceye_cn_dns(self) -> bool:
        requests.delete(url="https://api.ceye.io/v1/users/self/records?type=dns_records")
        info = self.exact_request(self.flag["flag"], type="dns")
        if info == self.value:
            return True
        else:
            return False

# sql判断
class Sql_scan:
    rules_dict = {}
    def __init__(self, headers, TIMEOUT):
        self.conn = requests.session()
        self.headers = headers
        self.TIMEOUT = TIMEOUT
        self._init_rules()

    def urlopen_get_html(self, url):
        try:
            self.request = self.conn.get(url, headers=self.headers, timeout=self.TIMEOUT, verify=False, allow_redirects=False)
            html = self.request.text
            status = self.request.status_code
            resp_len = len(html)
        except Exception as error:
            html = ''
            status = ''
            resp_len = ''
        finally:
            return html,status,resp_len

    def urlopen_post_html(self, url, data):
        try:
            self.request = self.conn.post(url, headers=self.headers, data=data, timeout=self.TIMEOUT, verify=False, allow_redirects=False)
            html = self.request.text
            status = self.request.status_code
            resp_len = len(html)
        except Exception as error:
            html = ''
            status = ''
            resp_len = ''
        finally:
            return html,status,resp_len

    def _init_rules(self):
        #Sql_scan.rules_dict = {}
        self.tree = ET.parse('./data/error.xml')
        self.root = self.tree.getroot()
        for child in self.root:
            temp_list = []
            temp_dict = {}
            temp_list.append(child.attrib['value'])
            #child.attrib['value']
            for neighbor in child.iter('error'):
                temp_list.append(neighbor.attrib['regexp'])
                #print(neighbor.attrib['regexp'])
            temp_dict[child.attrib['value']] = temp_list
            Sql_scan.rules_dict = {**Sql_scan.rules_dict, **temp_dict}

    def check_sql_exis(self, html, regx_list):
        for regx in regx_list:
            try:
                p_status = re.compile(regx)
                _ = p_status.search(html)
                if _:
                    return 1
            except Exception as e:
                continue
        return 0

#重定向输出类
#from settings import echo_threadLock
echo_threadLock = threading.Lock()
class TextRedirector(object):
    #global echo_threadLock
    def __init__(self, widget, tag="stdout", index="1"):
        #同步锁
        self.widget = widget
        self.tag = tag
        self.index = index
        #颜色定义
        self.widget.tag_config("red", foreground="red")
        self.widget.tag_config("white", foreground="white")
        self.widget.tag_config("green", foreground="green")
        self.widget.tag_config("black", foreground="black")
        self.widget.tag_config("yellow", foreground="yellow")
        self.widget.tag_config("blue", foreground="blue")
        self.widget.tag_config("orange", foreground="orange")
        self.widget.tag_config("pink", foreground="pink")
        self.widget.tag_config("cyan", foreground="cyan")
        self.widget.tag_config("magenta", foreground="magenta")
        #self.widget.tag_config("fuchsia", foreground="fuchsia")

    def write(self, str_raw):
        echo_threadLock.acquire() #获取锁
        if self.index == "2":#命令执行背景是黑色，字体是绿色。
            self.tag = 'white'
            self.widget.configure(state="normal")
            self.widget.insert(END, str_raw, (self.tag,))
            self.widget.configure(state="disabled")
            self.widget.see(END)
        else:
            self.tag = 'black'
            self.widget.configure(state="normal")
            self.widget.insert(END, str_raw, (self.tag,))
            self.widget.configure(state="disabled")
            self.widget.see(END)
        #flush
        self.widget.update()
        echo_threadLock.release() #释放锁

    def Colored(self, str_raw, color='black', end='\n'):
        #now = datetime.datetime.now()
        #str_raw = "["+str(now)[11:19]+"] " + " "+str_raw
        echo_threadLock.acquire() #获取锁
        if end == '':
            str_raw = str_raw.strip('\n')
        #logging.info(str_raw)
        self.tag = color
        self.widget.configure(state="normal")
        self.widget.insert(END, str_raw, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see(END)
        #flush
        self.widget.update()
        echo_threadLock.release() #释放锁

    #def flush(self):
    #    echo_threadLock.acquire() #获取锁
    #    self.widget.update()
    #    echo_threadLock.release() #释放锁

    def waitinh(self):
        echo_threadLock.acquire() #获取锁
        self.widget.configure(state="normal")
        self.widget.insert(END, str, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see(END)
        echo_threadLock.release() #释放锁

class FrameProgress(tk.Frame):
    def __init__(self, parent, Prolength=200, maximum=200, **cnf):
        tk.Frame.__init__(self, master=parent, **cnf)
        bg = parent.cget("background")

        s = ttk.Style()
        #s.theme_use("clam")
        #颜色随偏好修改 部分设置只在特定主题有效果,否则为默认绿色
        s.configure(
            "fp.Horizontal.TProgressbar", 
            troughcolor=bg, 
            background="#0078d7",
            lightcolor="#0078d7", 
            darkcolor="#0078d7", 
            relief=tk.GROOVE
        )

        self.pBar = ttk.Progressbar(self, 
                                    length=Prolength, 
                                    orient="horizontal", 
                                    mode="determinate", 
                                    maximum=maximum,
                                    style="fp.Horizontal.TProgressbar")
        
        #sticky="wens" 上面length 值会被忽略
        self.pBar.grid(row=0, column=0, sticky="w")

        #父组件的大小不由子组件决定
        self.grid_propagate(False)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

class URL():
    def __init__(self, url):
        parsed = urlparse(url)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc
        self.path = parsed.path
        self.params = parsed.params
        self.query = parsed.query
        self.fragment = parsed.fragment        
        if parsed.port and parsed.port != 0:
            self.port = parsed.port
        else:
            if self.scheme == b'https':
                self.port = 443
            else:
                self.port = 80

    @property
    def ProjectPath(self):
        """
        Project path
        :return:
        """
        return self.scheme+"://"+self.netloc+self.path[0:self.path.rindex('/')]
    
    @property
    def RootPath(self):
        """
        Root path
        :return:
        """
        return self.scheme+"://"+self.netloc
    
from tkinter import Tk    
#复制字符到Windows剪切板
def addToClipboard(text):
    r = Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append(text)
    r.update()
    r.destroy()

def seconds2hms(seconds):
    # 将秒数转换成时分秒
    # 返回类型为str类型
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return "%02d:%02d:%02d" % (h, m, s)

#颜色输出函数
def color(str, color='black', end='\n'):
    #自动添加\n换行符号,方便自动换行
    sys.stdout.Colored(str+'\n', color, end)

def random_name(index):
    h = "abcdefghijklmnopqrstuvwxyz0123456789"
    salt_cookie = ""
    for i in range(index):
        salt_cookie += random.choice(h)
    return salt_cookie

def Merge(dict1, dict2):
    res = {**dict1, **dict2} 
    return res

def byte_to_hex(pw):
    #pw = b'111111'
    temp = b''
    for x in pw:
        temp += binascii.a2b_hex('%02x' % int('{:08b}'.format(x)[::-1], 2))
    return temp

#使用ysoserial.jar 生成 payload
# return 'aced'
def ysoserial_payload(java_class, java_cmd, java_type='-jar'):
    command = "java {} ysoserial.jar {} \"{}\"".format(java_type,java_class,java_cmd)
    popen = subprocess.Popen(command, stdout=subprocess.PIPE ,shell=True,close_fds=True)
    out,drr = popen.communicate()
    return out
    #return binascii.hexlify(out).decode()

#github登录功能函数
def login_github(username,password):#登陆Github
    #初始化参数
    login_url = 'https://github.com/login'
    session_url = 'https://github.com/session'
    try:
        #获取session
        s = requests.session()
        resp = s.get(login_url).text
        dom_tree = etree.HTML(resp)
        key = dom_tree.xpath('//input[@name="authenticity_token"]/@value')
        user_data = {
            'commit': 'Sign in',
            'utf8': '✓',
            'authenticity_token': key,
            'login': username,
            'password': password
        }
        #发送数据并登陆
        s.post(session_url,data=user_data)
        s.get('https://github.com/settings/profile')
        return s
    except Exception as e:
        print('[-]产生异常，请检查网络设置及用户名和密码')
        #error_Record(str(e), traceback.format_exc())

def open_html(fileURL):
    '''
    Save as HTML file and open in the browser
    '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull, os.O_RDWR)
    try:
        #s = Template(open('%s/template.html' % sys.path[0], 'r').read())
        #s = Template(template)
        #text_file = open(fileURL, "wb")
        #text_file.write(html.encode('utf8'))
        #text_file.write(s.substitute(content=html).encode('utf8'))
        #text_file.close()
        #print("URL to access output: file://%s" % os.path.abspath(args.output))
        file = "file:///%s" % os.path.abspath(fileURL)
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(["xdg-open", file])
        else:
            webbrowser.open(file)
    except Exception as e:
        print("Output can't be saved in %s \
            due to exception: %s" % (fileURL, e))
    finally:
        os.dup2(hide, 1)
#补足8位并返回bytes =================>如果是3DES，要import DES3,然后 add_to_16即可
def add_to_8(value):
    while len(value) % 8 != 0:
        value = value + "\0"
    return value.encode(encoding='utf-8')

# str不是16的倍数那就补足为16的倍数
def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes

#加密方法
def aes_enc(text,key):
    from Crypto.Cipher import AES
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    #先进行aes加密
    encrypt_aes = aes.encrypt(add_to_16(text))
    #用base64转成字符串形式
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    return encrypted_text

#解密方法
def aes_dec(text,key):
    # 初始化加密器
    from Crypto.Cipher import AES
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    #优先逆向解密base64成bytes
    base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
    #
    decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8') # 执行解密密并转码返回str
    decrypted_text=decrypted_text.rstrip('\0')
    return decrypted_text

#DES加密(还有点问题)
def des_enc(text,ENCRYPT_KEY):
    text = request.quote(text)
    aes = DES.new(add_to_8(ENCRYPT_KEY),DES.MODE_ECB)

    encrypt_aec = aes.encrypt(add_to_8(text))
    encrypt_text = str(base64.encodebytes(encrypt_aec),encoding="utf-8").strip()
    return encrypt_text

#DES解密
def des_dec(text,ENCRYPT_KEY):
    aes = DES.new(add_to_8(ENCRYPT_KEY),DES.MODE_ECB)
    decrypt_aec = base64.decodebytes(text.encode(encoding='utf-8'))
    decrypt_text = aes.decrypt(decrypt_aec)
    #去除末尾的\x07
    decrypt_text = str(decrypt_text[:-decrypt_text[-1]],encoding='utf-8')
    decrypt_text = request.unquote(decrypt_text)
    return decrypt_text


def get_sha1(string):
    from hashlib import sha1
    s1=sha1()
    s1.update(string.encode('utf8'))
    return s1.hexdigest()

def get_middle_text(text, prefix, suffix, index=0):
    """
    Simple implementation of obtaining intermediate text
    :param text:Full text to get
    :param prefix:To get the first part of the text
    :param suffix: To get the second half of the text
    :param index: Where to get it from
    :return:
    """
    try:
        index_1 = text.index(prefix, index)
        index_2 = text.index(suffix, index_1 + len(prefix))
    except ValueError:
        # logger.log(CUSTOM_LOGGING.ERROR, "text not found pro:{} suffix:{}".format(prefix, suffix))
        return ''
    return text[index_1 + len(prefix):index_2]

#打开脚本目录
def LoadCMD(folder_name):
    from settings import rootPath
    start_directory = rootPath + folder_name
    os.startfile(start_directory)
    
#删除text组件的内容
def delText(text):
    text.configure(state="normal")
    text.delete('1.0','end')
    text.configure(state="disabled")
    
def thread_it(func, **kwargs):
    t = threading.Thread(target=func,kwargs=kwargs)
    #守护--就算主界面关闭，线程也会留守后台运行（不对!）
    t.setDaemon(True)
    #启动
    t.start()