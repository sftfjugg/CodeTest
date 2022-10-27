import subprocess
import os,json
from tkinter.messagebox import NO
###获取项目路径###
rootPath = os.getcwd()
http_url = ''
http_status = ''
page_title = ''
content_length = ''
content_type = ''
webserver = ''
def check(**kwargs):
    httpx_command = '"'+rootPath + '/scan/httpx.exe" -status-code -content-length -title -cdn -ip -follow-host-redirects -json'
    httpx_command = 'echo {} | {}'.format(kwargs['url'], httpx_command)
    popen = subprocess.Popen(httpx_command, stdout=subprocess.PIPE ,shell=True,close_fds=True)
    out, drr = popen.communicate()
    if out is None:
        print('[*] {} timeout'.format(kwargs['url']))
        return
    result = out.decode('utf-8',errors='ignore')
    json_st = json.loads(result)
    if 'url' in json_st:
        http_url = json_st['url']
    if 'status-code' in json_st:
        http_status = json_st['status-code']
    if 'title' in json_st:
        page_title = json_st['title']
    if 'content-length' in json_st:
        content_length = json_st['content-length']
    if 'content-type' in json_st:
        content_type = json_st['content-type']
    if 'webserver' in json_st:
        webserver = json_st['webserver']
    print('[*] {} [{}] [{}] [{}]'.format(http_url, http_status, page_title, content_length))
    
    
    