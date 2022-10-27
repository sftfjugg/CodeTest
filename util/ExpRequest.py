# -*- coding: utf-8 -*-
from settings import Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_cookie
from ClassCongregation import color
from requests.models import Response
from util.urlType import UrlType
from util.Bytes import Bytes
from lxml import etree

import requests
import datetime
import random
import time
import sys
import re

requests.packages.urllib3.disable_warnings()

class ExpRequest(object):
    
    def __init__(self, output=None):
        self.response = Response()
        self.output = output
        self.timeout = int(Ent_B_Top_timeout.get())
        self.retry_time = int(Ent_B_Top_retry_time.get())
        self.retry_interval = int(Ent_B_Top_retry_interval.get())
        #update header
        self.auth = Ent_B_Top_cookie.get()
        if ':' in self.auth:
            key = self.auth.split(':')[0].strip()
            value = self.auth.split(':')[1].strip()
            self.auth = {key:value}
        
    @property
    def user_agent(self):
        """
        return an User-Agent at random
        :return:
        """
        ua_list = [
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
            'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        ]
        return random.choice(ua_list)

    @property
    def header(self):
        """
        basic header
        :return:
        """
        return {'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Accept-Language': 'zh-CN,zh;q=0.8',
                'Accept-Encoding' : 'gzip, deflate',}

    def get(self, url, headers=None, *args, **kwargs):
        """
        get method
        :param url: target url
        :param header: headers
        :param timeout: network timeout
        :return:
        """
        header = self.header
        timeout = self.timeout
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        
        if headers and isinstance(headers, dict):
            header.update(headers)
        if self.auth and isinstance(self.auth, dict):
            for key, value in self.auth.items():
                if key not in header:
                    header.update({key:value})
        while True:
            try:
                self.response = requests.get(url, headers=header, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                time.sleep(retry_interval)

    def post(self, url, headers=None, *args, **kwargs):
        """
        post method
        :param url: target url
        :param headers: headers
        :param timeout: network timeout
        :return:
        """
        header = self.header
        timeout = self.timeout
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        # dict本身就代表数据存储的内存区域
        header.update({'Content-Type':'application/x-www-form-urlencoded'})
        if headers and isinstance(headers, dict):
            header.update(headers)
        if self.auth and isinstance(self.auth, dict):
            for key, value in self.auth.items():
                if key not in header:
                    header.update({key:value})
        while True:
            try:
                self.response = requests.post(url, headers=header, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                time.sleep(retry_interval)

    def put(self, url, headers=None, *args, **kwargs):
        """
        put method
        :param url: target url
        :param headers: headers
        :param timeout: network timeout
        :return:
        """
        header = self.header
        timeout = self.timeout
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        if headers and isinstance(headers, dict):
            header.update(headers)
        if self.auth and isinstance(self.auth, dict):
            for key, value in self.auth.items():
                if key not in header:
                    header.update({key:value})
        while True:
            try:
                self.response = requests.put(url, headers=header, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                time.sleep(retry_interval)  

    def delete(self, url, headers=None, *args, **kwargs):
        """
        delete method
        :param url: target url
        :param headers: headers
        :param timeout: network timeout
        :return:
        """
        header = self.header
        timeout = self.timeout
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        if headers and isinstance(headers, dict):
            header.update(headers)
        if self.auth and isinstance(self.auth, dict):
            for key, value in self.auth.items():
                if key not in header:
                    header.update({key:value})
        while True:
            try:
                self.response = requests.delete(url, headers=header, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                time.sleep(retry_interval) 
    @property
    def code(self):
        encodings = requests.utils.get_encodings_from_content(self.response.text)
        if encodings:
            return encodings[0]
        else:
            return self.response.apparent_encoding

    @property
    def status(self):
        return self.response.status_code

    @property
    def status_code(self):
        return self.response.status_code

    @property
    def headers(self):
        return self.response.headers
    
    @property
    def content_type(self):
        try:
            return self.response.headers['Content-Type']
        except:
            return ''
    
    @property
    def title(self):
        return "".join(re.findall('<title>(.+)</title>',self.response.text))

    @property
    def tree(self):
        return etree.HTML(self.response.content.decode(self.code, 'ignore'))

    @property
    def text(self):
        return self.response.text

    @property
    def json(self):
        try:
            return self.response.json()
        except Exception as e:
            return {}

    @property
    def body(self):
        return Bytes(self.response.text.encode(encoding='UTF-8', errors='ignore'))
    
    @property
    def raw(self):
        return None
    
    @property
    def url(self):
        return UrlType(self.url)
    
    @property
    def method(self):
        return self.method
    
    @property
    def latency(self):
        return self.latency
    
#结果输出
class Output(object):
    def __init__(self, url='', appname='', pocname='', last_status='fail'):
        self.error_msg = tuple()
        self.result = {}
        self.params = {}
        self.status = {}
        self.url = url
        #组件类型
        self.appname = appname
        #漏洞名称
        self.pocname = pocname
        #检测状态 -> 默认为fail
        self.last_status = last_status
        #检测时间
        self.last_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def result_error(self, error=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ error, 'cyan')
        self.last_status = 'fail'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def timeout_output(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" check failed because timeout !!!", 'cyan')
        self.last_status = 'fail'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def connection_output(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" check failed because unable to connect !!!", 'cyan')
        self.last_status = 'fail'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def error_output(self, error=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" "+ error +" !!!", 'cyan')
        self.last_status = 'fail'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def no_echo_success(self, method='', info=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[+] The " + self.url + " is "+ self.pocname +" ["+ method +"] "+ info, 'green')
        self.last_status = 'success'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def echo_success(self, method='', info=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[+] The "+ self.url +" is "+ self.pocname +" ["+ method +"] "+ info +" echo_success", 'green')
        self.last_status = 'success'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def fail(self, info=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[-] The " + self.url + " no "+ self.pocname + " " + info, 'magenta')
        self.last_status = 'fail'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def to_dict(self):
        return self.__dict__

#日志
class Logger(object):
    @staticmethod
    def error(info):
        now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sys.stderr.write(now_time + ' [ERROR] '+ info +'\n')
        
#时间类
class Timed(object):
    @staticmethod
    def timed(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    @staticmethod
    def timed_line(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    @staticmethod
    def no_color_timed(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        print("["+str(now)[11:19]+"] ",end="")