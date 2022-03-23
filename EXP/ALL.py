import sys,importlib,glob,os,datetime
import util.globalvar as GlobalVar
sys.path.append('../')
from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
from ClassCongregation import color

vuln_scripts = []
exp_scripts = []
thread_list = []
result_list = []
check_list = []
for _ in glob.glob('EXP/*.py'):
    script_name = os.path.basename(_).replace('.py', '')
    if script_name != 'ALL' and script_name != '__init__':
        vuln_name = importlib.import_module('.%s'%script_name, package='EXP')
        exp_scripts.append(script_name)
        vuln_scripts.append(vuln_name)

def check(**kwargs):
    result_list.append('----------------------------')
    now = datetime.datetime.now()
    color ("["+str(now)[11:19]+"] " + "[+] Scanning target domain "+kwargs['url'], 'green')
    pool = ThreadPoolExecutor(int(kwargs['pool_num']))
    
    #for i in vuln_scripts:
    #    func = getattr(i, 'check')
    #    thread_list.append(pool.submit(func(**kwargs)))
    #GlobalVar.set_value('thread_list', thread_list)
    #wait(thread_list, return_when=ALL_COMPLETED)
    
    for i in vuln_scripts:
        check_list.append(getattr(i, 'check'))
    
    for data in pool.map(lambda func:func(**kwargs), check_list):
        result_list.append(data)
    #for task in thread_list:
    #    #去除取消掉的future任务
    #    if task.cancelled() == False:
    #        result_list.append(task.result())
    result_list.append('----------------------------')
    return '\n'.join(result_list)