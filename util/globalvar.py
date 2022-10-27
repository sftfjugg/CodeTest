#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
全局变量: GlobalVar
# """
# import threading
# threadLock = threading.Lock()
def _init():
    global _global_dict
    _global_dict = {}

def set_value(name, value):
    _global_dict[name] = value

def get_value(name, defValue=''):
    try:
        return _global_dict[name]
    except KeyError:
        return defValue

def add_value(name, value):
    #获取锁
    # threadLock.acquire()
    if isinstance(_global_dict[name], dict) and isinstance(value, dict):
        _global_dict[name].update(value)
    elif isinstance(_global_dict[name], list) and isinstance(value, list):
        _global_dict[name] = _global_dict[name] + value
    #释放锁
    # threadLock.release()