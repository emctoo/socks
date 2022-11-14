#!/usr/bin/env python
# coding: utf8

# curl -vvv --socks5 127.0.0.1:8888 jd.com/

import argparse
import logging
import socket

# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(filename)s:%(lineno)s - %(message)s'))
handler.setLevel(logging.DEBUG)

log = logging.getLogger('client')
log.addHandler(handler)
log.setLevel(logging.DEBUG)


import socks

def create_connection(address, timeout=None, source_address=None):
    sock = socks.socksocket()
    sock.connect(address)
    return sock

parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('-p', dest='port', type=int, default=80)
# parser.add_argument('--proxy', type=str, default='socks5://192.168.8.46:2080')
parser.add_argument('--proxy', type=str, default='socks5://127.0.0.1:2080')

args = parser.parse_args()
log.info('host: %s, port: %s', args.host, args.port)

proxy_protocol = args.proxy.split(':', 1)[0]
proxy_host, proxy_port = args.proxy.rsplit('/', 1)[-1].split(':')
proxy_port = int(proxy_port)
log.info('proxy: %s://%s:%s', proxy_protocol, proxy_host, proxy_port)

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_host, proxy_port)

# patch the socket module
socket.socket = socks.socksocket
socket.create_connection = create_connection

try:
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.host, args.port))
    message = b'GET / HTTP/1.0\r\n\r\n'
    s.sendall(message)
    reply = s.recv(4069)
    print(reply.decode())
except KeyboardInterrupt:
    print('\ruser interrupted, bye')
except Exception as e:
    print(e)