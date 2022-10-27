#coding:utf-8
import os
import  execjs
import threading

passfile = "top100password.txt"
jsfile = "md5.js"
encode_fun = "hex_md5"

pwd = "ZzxS@01#{1#2$3%4(5)6@7!poeeww$3%4(5)djjkkldss}"

def info():
    #os.environ["EXECJS_RUNTIME"] = 'Phantomjs'
    print("[+]============================================================")
    print("[+] Python调用JS加密password文件内容                           ")
    print("[+] passfile : 密码字典                                        ")
    print("[+] jsfile : JS文件                                           ")
    print("[+] encode_fun : 加密函数                                     ")
    print("[+]============================================================")
    print("                                                                             ")

def Encode(jsfile, passfile, enpwd):
    os.environ["EXECJS_RUNTIME"] = 'Phantomjs'
    jsfile = './POC/js_examples/' + jsfile
    passfile = './POC/js_examples/' + passfile
    #jsfile = './js_examples/' + jsfile
    #passfile = './js_examples/' + passfile
    print("[+] 正在进行加密，请稍后......")
    with open (jsfile,'r') as strjs:
        src = strjs.read()
        #phantom = execjs.get('PhantomJS')	#调用JS依赖环境
        #getpass = phantom.compile(src)	#编译执行js脚本
        getpass = execjs.compile(src)
        with open(passfile, 'r') as strpass:
            for passwd in strpass.readlines():
                try:
                    passwd = passwd.strip() + "{1#2$3%4(5)6@7!poeeww$3%4(5)djjkkldss}"
                    mypass = getpass.call(encode_fun, passwd)	#传递参数
                    if enpwd == mypass:
                        print("[+] %s 破解成功: %s"%(enpwd,passwd))
                        return
                    else:
                        print("[+] %s 破解失败"%(passwd))
                except:
                    print("[-] %s 加密失败"%passwd)
                    continue
            print("[+] 加密完成")

#对单一密码进行加密
def passstring(jsfile, password):
    jsfile = './POC/js_examples/' + jsfile
    print("[+] 正在进行加密，请稍后......")
    with open (jsfile,'r') as strjs:
        src = strjs.read()
        phantom = execjs.get('PhantomJS')	#调用JS依赖环境
        getpass = phantom.compile(src)	#编译执行js脚本
        mypass = getpass.call(encode_fun, password)	#传递参数
        print("[+] %s 加密完成: %s"%(pwd,mypass))

info()
def check(**kwargs):
    if pwd != "":
        passstring(jsfile, pwd)
    else:
        t = threading.Thread(target=Encode, args=(jsfile, passfile, kwargs['url']))
        t.start()

if __name__ == "__main__":
    pd = ""
    passstring(jsfile=jsfile,password=pd)








