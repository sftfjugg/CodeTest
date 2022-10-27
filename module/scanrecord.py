import json

class ScanRecord(object):

    def __init__(self, target, appName, pocname, last_status, last_time):
        #排列序号
        #self._id = id
        #目标地址
        self._target = target
        #组件类型
        self._appName = appName
        #漏洞名称
        self._pocname = pocname
        #检测状态
        self._last_status = last_status
        #返回状态码
        #self._httpstatus = httpstatus
        #验证时间
        self._last_time = last_time
        #备注
        #self._remark = remark
    
    @classmethod
    def createFromJson(cls, scan_json):
        _dict = json.loads(scan_json)
        return cls(target=_dict.get("target", ""),
                   last_status=_dict.get("last_status", ""),
                   appName=_dict.get("appName", ""),
                   pocname=_dict.get("pocname", ""),
                   #httpstatus=_dict.get("httpstatus", 0),
                   last_time=_dict.get("last_time", ""),
                   )

    #@property
    #def id(self):
    #    """ 标识符 """
    #    return self._id

    @property
    def target(self):
        """ url """
        return self._target

    @property
    def appName(self):
        """ 组件名称 """
        return self._appName

    @property
    def pocname(self):
        """ 漏洞名称 """
        return self._pocname

    @property
    def last_status(self):
        """ 最后一次检测结果  success -> 成功; faile -> 失败"""
        return self._last_status

    #@property
    #def httpstatus(self):
    #    """ 状态码 """
    #    return self._httpstatus

    @property
    def last_time(self):
        """ 最后一次检测时间 """
        return self._last_time

    #@property
    #def remark(self):
    #    """ 备注 """
    #    return self._remark

    @property
    def to_dict(self):
        """ 属性字典 """
        return {"target": self.target,
                "last_status": self.last_status,
                "appName": self.appName,
                "pocname": self.pocname,
                #"httpstatus": self.httpstatus,
                "last_time": self.last_time,
            }

    @property
    def to_json(self):
        """ 属性json格式 """
        return json.dumps(self.to_dict, ensure_ascii=False)

    @last_status.setter
    def last_status(self, value):
        self._last_status = value

    #@httpstatus.setter
    #def httpstatus(self, value):
    #    self._httpstatus = value

    @last_time.setter
    def last_time(self, value):
        self._last_time = value

    #@remark.setter
    #def remark(self, value):
    #    self._remark = value