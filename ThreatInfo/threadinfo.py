# -*- coding: utf-8 -*-
import json

class Threadinfo(object):

    def __init__(self, ip="None", domain="None", ipWhois={}, domainWhois={}, beianWhois={}, threatbook={}, aiqicha=[]):
        #基础属性
        self._ip = ip
        self._domain = domain
        #具体画像
        self._ipWhois = ipWhois
        self._domainWhois = domainWhois
        self._beianWhois = beianWhois
        self._aiqicha = aiqicha
        self._threatbook = threatbook

    @classmethod
    def createFromJson(cls, threadinfo_json):
        _dict = json.loads(threadinfo_json)
        return cls(ip=_dict.get("ip", ""),
                   domain=_dict.get("domain", ""),
                   ipWhois=_dict.get("ipWhois", {}),
                   domainWhois=_dict.get("domainWhois", {}),
                   beianWhois=_dict.get("beianWhois", {}),
                   aiqicha=_dict.get("aiqicha", []),
                   threatbook=_dict.get("threatbook",{})
        )

    @property
    def ip(self):
        """ ip地址 """
        return self._ip

    @property
    def domain(self):
        """ 域名 """
        return self._domain

    @property
    def ipWhois(self):
        """ ip whois """
        return self._ipWhois
    
    @property
    def domainWhois(self):
        """ domain whois """
        return self._domainWhois

    @property
    def beianWhois(self):
        """ 备案查询 """
        return self._beianWhois

    @property
    def aiqicha(self):
        """ 备案查询 """
        return self._aiqicha

    @property
    def threatbook(self):
        """ 威胁分析 """
        return self._threatbook

    @property
    def to_dict(self):
        """ 属性字典 """
        return {"ip": self.ip,
                "domain": self.domain,
                "ipWhois":self.ipWhois,
                "domainWhois":self.domainWhois,
                "beianWhois":self.beianWhois,
                "threatbook":self.threatbook,
                "aiqicha":self.aiqicha,
        }
        
    @property
    def json_beautify(self):
        """ 属性字典 """
        return json.dumps(self.to_dict, indent=4, separators=(',', ': '), ensure_ascii=False)

    @property
    def to_json(self):
        """ 属性json格式 """
        return json.dumps(self.to_dict, ensure_ascii=False)
    
    @ip.setter
    def ip(self, value):
        self._ip = value

    @domain.setter
    def domain(self, value):
        self._domain = value
        
    @ipWhois.setter
    def ipWhois(self, value):
        self._ipWhois = value

    @domainWhois.setter
    def domainWhois(self, value):
        self._domainWhois = value
        
    @beianWhois.setter
    def beianWhois(self, value):
        self._beianWhois = value

    @threatbook.setter
    def threatbook(self, value):
        self._threatbook = value
        
    @aiqicha.setter
    def aiqicha(self, value):
        self._aiqicha = value