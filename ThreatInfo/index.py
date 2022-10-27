from threadinfo import Threadinfo
from check import DoCollect
from concurrent.futures import ThreadPoolExecutor
import time
import os
# os.environ['HTTP_PROXY'] = '127.0.0.1:8080'
# os.environ['HTTPS_PROXY'] = '127.0.0.1:8080'

a = Threadinfo(
    ip="85.31.46.143",
    # domain="www.douyin.com.w.kunluncan.com",
    )
temp_list = [
    {"ip":"80.82.77.139"},
    {"ip":"101.84.30.9"},
    {"ip":"106.11.172.5"},
    {"ip":"51.81.46.110"},
    {"ip":"110.93.150.181"},
    {"ip":"137.184.177.44"},
    {"ip":"64.227.23.61"},
]
index = [Threadinfo(**kwargs) for kwargs in temp_list]
index = [a]

# # executor = ThreadPoolExecutor(max_workers = 30)
# # for data in executor.map(DoCollect.ipaddressCollect, index):
# #     result_list.append(data)#汇聚结果

# for proxy in index:
#     print(proxy.ipaddress)
# for func in dir(DoCollect):
#     if not func.startswith("__"):
#         getattr(DoCollect, func)(a)
for a in index:
    DoCollect.domain2ipCollect(a)
    DoCollect.ip2domainCollect(a)
    DoCollect.ipWhoisCollect(a)
    DoCollect.domainWhoisCollect(a)
    DoCollect.beianWhoisCollect(a)
    DoCollect.aiqichaCollect(a)
    print(a.json_beautify)
    time.sleep(0.5)

