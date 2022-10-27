# -*- coding: utf-8 -*-
from ThreatInfo.validator import InfoCollect

flag = ['None','Error','CDN','',{},[],None]

class DoCollect(object):
    """ 收集信息 """
    @classmethod
    def domain2ipCollect(cls, threadinfo):
        #域名解析ip
        if threadinfo.ip in flag and threadinfo.domain not in flag:
            for func in InfoCollect.domain2ip_Collect:
                ip = func(threadinfo.domain)
                if ip not in flag:
                    threadinfo.ip = ip
                    return True
            threadinfo.ip = ip
            return False

    @classmethod
    def ip2domainCollect(cls, threadinfo):
        #ip反查域名
        if threadinfo.ip not in flag and threadinfo.domain in flag:
            for func in InfoCollect.ip2domain_Collect:
                domain = func(threadinfo.ip)
                if domain not in flag:
                    threadinfo.domain = domain
                    return True
            threadinfo.domain = domain
            return False

    # @classmethod
    # def spaceCollect(cls, threadinfo):
    #     if threadinfo.ip not in flag:
    #         for func in InfoCollect.space_Collect:
    #             space = func(threadinfo.ip)
    #             if space not in flag:
    #                 threadinfo.space = space
    #                 return True
    #         threadinfo.space = space
    #         return False

    @classmethod
    def ipWhoisCollect(cls, threadinfo):
        #ipwhois查询
        if threadinfo.ip not in flag:
            for func in InfoCollect.ipWhois_Collect:
                ipWhois = func(threadinfo.ip)
                if ipWhois not in flag:
                    threadinfo.ipWhois = ipWhois
                    return True
            threadinfo.ipWhois = ipWhois
            return False

    @classmethod
    def beianWhoisCollect(cls, threadinfo):
        #备案查询
        if threadinfo.domain not in flag:
            for func in InfoCollect.beianWhois_Collect:
                beianWhois = func(threadinfo.domain)
                if beianWhois not in flag:
                    threadinfo.beianWhois = beianWhois
                    return True
            threadinfo.beianWhois = beianWhois
            return False

    @classmethod
    def domainWhoisCollect(cls, threadinfo):
        #域名whois查询
        if threadinfo.domain not in flag:
            for func in InfoCollect.domainWhois_Collect:
                domainWhois = func(threadinfo.domain)
                if domainWhois not in flag:
                    threadinfo.domainWhois = domainWhois
                    return True
            threadinfo.domainWhois = domainWhois
            return False

    @classmethod
    def threatbookCollect(cls, threadinfo):
        #微步-威胁分析
        if threadinfo.ip not in flag:
            for func in InfoCollect.threatbook_Collect:
                threatbook = func(threadinfo.ip)
                if threatbook not in flag:
                    threadinfo.threatbook = threatbook
                    return True
            threadinfo.threatbook = threatbook
            return False

    @classmethod
    def aiqichaCollect(cls, threadinfo):
        #爱企查
        if threadinfo.beianWhois not in flag:
            for func in InfoCollect.aiqicha_Collect:
                aiqicha = func(threadinfo.beianWhois['beianName'])
                if aiqicha not in flag:
                    threadinfo.aiqicha = aiqicha
                    return True
            threadinfo.aiqicha = aiqicha
            return False
