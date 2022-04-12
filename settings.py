from concurrent.futures import thread
from tkinter import StringVar,IntVar
import os
import sys
from tkinter.messagebox import NO

###获取项目路径###
curPath = os.path.dirname(os.path.realpath(sys.executable))
#当前python.exe执行路径
rootPath = os.getcwd()

#代理网站
Proxy_page = IntVar(value=1)#爬取代理的页数
Proxy_webtitle = StringVar(value='米扑代理')#爬取代理的页数
Proxy_web = {
    '米扑代理' : 'freeProxy01',
    '66代理' : 'freeProxy02',
    'pzzqz' : 'freeProxy03',
    '神鸡代理' : 'freeProxy04',
    '快代理' : 'freeProxy05',
    '极速代理' : 'freeProxy06',
    '云代理' : 'freeProxy07',
    '小幻代理' : 'freeProxy08',
    '免费代理库' : 'freeProxy09',
    '89免费代理' : 'freeProxy13',
    '西拉代理' : 'freeProxy14',
}

#代理界面_Proxy
Proxy_type = StringVar(value='HTTP/HTTPS')#代理界面_代理类型_HTTP
Proxy_CheckVar1 = IntVar()#代理界面_控制代理开关1
Proxy_CheckVar2 = IntVar()#代理界面_控制代理开关0
Proxy_addr = StringVar(value='127.0.0.1')#代理界面_代理IP
Proxy_port = StringVar(value='8080')#代理界面_代理端口

#漏洞扫描界面_A
Ent_A_Top_thread = StringVar(value='3')#漏洞扫描界面_顶部_线程_3
Ent_A_Top_Text = '''
   ____          _     _____         _   
  / ___|___   __| | __|_   _|__  ___| |_ 
 | |   / _ \ / _` |/ _ \| |/ _ \/ __| __|
 | |__| (_) | (_| |  __/| |  __/\__ \ |_ 
  \____\___/ \__,_|\___||_|\___||___/\__| v0.2
[*]1.信息收集 -> 收集信息, 打点
[*]2.漏洞扫描 -> 扫描漏洞, 结果会保存在仓库中, 等待进一步利用
[*]3.漏洞测试 -> 验证漏洞, 生成exp脚本
[*]4.漏洞仓库 -> 保存扫描结果, 支持批量利用
[*]5.漏洞笔记 -> 存放常用语句
--------------------------------------------------Main--------------------------------------------------'''

#漏洞利用界面_B
Ent_B_Top_url = StringVar(value='')#漏洞利用界面_顶部_目标地址
Ent_B_Top_cookie = StringVar(value='暂时无用')#漏洞利用界面_顶部_Cookie
Ent_B_Top_vulname = StringVar(value='请选择漏洞名称')#漏洞利用界面_顶部_漏洞名称_请选择漏洞名称
Ent_B_Top_vulmethod = StringVar(value='ALL')#漏洞利用界面_顶部_调用方法_ALL
Ent_B_Top_funtype = StringVar(value='False')#漏洞利用界面_顶部_exp功能_False
Ent_B_Top_timeout = StringVar(value='10')#漏洞扫描界面_顶部_超时时间_5
Ent_B_Top_retry_time = StringVar(value='1')#漏洞扫描界面_顶部_重试次数_1
Ent_B_Top_retry_interval = StringVar(value='1')#漏洞扫描界面_顶部_重试间隔_1
Ent_B_Top_thread_pool = StringVar(value='10')#漏洞扫描界面_顶部_线程数量_10
Ent_B_Bottom_Left_cmd = StringVar()#漏洞利用界面_底部_CMD命令输入框
Ent_B_Bottom_terminal_cmd = StringVar()#漏洞利用界面_终端_CMD命令输入框

#漏洞测试界面_C
Ent_C_Top_url = StringVar(value='http://httpbin.org')#漏洞测试界面_顶部_目标地址
Ent_C_Top_path = StringVar(value='/ip')#漏洞测试界面_顶部_路径
Ent_C_Top_reqmethod = StringVar(value='GET')#漏洞测试界面_顶部_请求方法类型_GET
Ent_C_Top_vulname = StringVar(value='')#漏洞测试界面_顶部_脚本名称
Ent_C_Top_cmsname = StringVar(value='')#漏洞测试界面_顶部_CMS名称
Ent_C_Top_cvename = StringVar(value='cve_')#漏洞测试界面_顶部_CVE编号
Ent_C_Top_version = StringVar(value='app=""')#漏洞测试界面_顶部_版本信息
Ent_C_Top_info = StringVar(value='命令执行描述')#漏洞测试界面_顶部_info_命令执行描述
Ent_C_Top_template = StringVar(value='请选择模板')#漏洞测试界面_顶部_template_请选择模板

#测试
Ent_Cmds_Top_type = StringVar()#命令控制台界面_顶部_漏洞类型
Ent_Cmds_Top_typevar = StringVar(value='yy yang haha 1 2 3 4 5 7 8 0')#命令控制台界面_顶部_漏洞类型值

#反序列化利用界面
Ent_yso_Top_type = StringVar(value='-jar')#ysoserial代码生成界面_顶部_类型
Ent_yso_Top_class = StringVar(value='利用链类')#ysoserial代码生成界面_顶部_利用链类
Ent_yso_Top_cmd = StringVar(value='whoami')#ysoserial代码生成界面_顶部_命令

#TCP调试界面
TCP_Debug_IP = StringVar(value='127.0.0.1')#TCP调试界面_IP地址
TCP_Debug_PORT = IntVar(value=80)#TCP调试界面_端口
TCP_Debug_PKT_BUFF_SIZE = IntVar(value=2048)#TCP调试界面_接收缓冲区大小

#代理变量
variable_dict = {
    "Proxy_CheckVar1" : Proxy_CheckVar1, 
    "Proxy_CheckVar2" : Proxy_CheckVar2, 
    "PROXY_TYPE" : Proxy_type, 
    "Proxy_addr" : Proxy_addr,
    "Proxy_port" : Proxy_port,
    "Proxy_page" : Proxy_page,
    "Proxy_webtitle" : Proxy_webtitle,
}
#全局空间
#Globals = globals()

#界面对象
exp = None
mycheck = None
mynote = None
myvuldatabase = None
myurls= None
myproxy= None
createexp = None

#保存GitHub登录后的状态
github_now = None
#EXP下的脚本列表
exp_scripts = ['ALL']
#EXP下的脚本下的CVE编号
exp_scripts_cve = ['ALL']
#EXP下加载的脚本对象
myexp_vuln = None