from ClassCongregation import color
import sys,importlib,glob,os,datetime
sys.path.append('../')

vuln_scripts = []
exp_scripts = []
for _ in glob.glob('EXP/*.py'):
    script_name = os.path.basename(_).replace('.py', '')
    if script_name != 'ALL' and script_name != '__init__':
        vuln_name = importlib.import_module('.%s'%script_name, package='EXP')
        exp_scripts.append(script_name)
        vuln_scripts.append(vuln_name)

def check(**kwargs):
    now = datetime.datetime.now()
    color ("["+str(now)[11:19]+"] " + "[+] Scanning target domain "+kwargs['url'], 'green')
    #填充非多线程
    for script in vuln_scripts:
        getattr(script, 'check')(**kwargs)