from impacket import smb, smbconnection, nt_errors
from impacket.nmb import NetBIOSError
from impacket.smbconnection import *
from struct import pack
from mysmb import MYSMB
from IPy import IP
import sys,time
import threading
import errno

USERNAME = ''
PASSWORD = ''

def smbcheck(target):
    if True:
        conn = MYSMB(target)
        try:
            conn.login(USERNAME, PASSWORD)
        except smb.SessionError as e:
            print('Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])
            #pass
        finally:
            #print('OS: ' + conn.get_server_os())
            TragetOS = '(' + conn.get_server_os()+')'

        tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
        conn.set_default_tid(tid)

        # test if target is vulnerable
        TRANS_PEEK_NMPIPE = 0x23
        recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
        status = recvPkt.getNTStatus()
        if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
            #print('The target is not patched')
            CheckResult = 'MS17-010\t'+TragetOS

        return CheckResult

def GetSmbVul(ip): 
    # output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()
    # for w in output:
        # if str(w).upper().find('TTL')>=0:
            #print "online "+ip
    try:
        SmbVul=smbcheck(ip)
        if SmbVul != None:
            print('%s\t%s'%(ip,SmbVul))
    except:
        pass


def ScanSmbVul(ip): 
    for add in [str(i) for i in IP(ip)]:
        threading._start_new_thread(GetSmbVul,(add,))
        time.sleep(0.1)




def CscanSMBver(ip):
    for add in [str(i) for i in IP(ip)]:
        threading._start_new_thread(smbVersion,(add,))
        time.sleep(0.1)

def smbVersion(rhost):
    host = rhost
    port=445
    try:
        smb = SMBConnection(host, host, sess_port=port)
    except NetBIOSError:
        return
    except socket.error as v:
        error_code = v[0]
        if error_code == errno.ECONNREFUSED:
            return
        else:
            return
    dialect = smb.getDialect()
    if dialect == SMB_DIALECT:
        print(host + "\tSMBv1 ")
    elif dialect == SMB2_DIALECT_002:
        print(host + "\tSMBv2.0 ")
    elif dialect == SMB2_DIALECT_21:
        print(host + "\tSMBv2.1 ")
    else:
        print(host + "\tSMBv3.0 ")

if __name__ == "__main__":
    #CscanSMBver('127.0.0.1')
    ScanSmbVul('127.0.0.1')