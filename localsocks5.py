#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-04-27 22:22:31
# @Version : 1.0

from __future__ import print_function

import struct
# import signal
import sys
import gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
import gevent
from gevent.server import StreamServer
from gevent import select, socket
from gevent.socket import gethostbyname
from ws4py.client.geventclient import WebSocketClient
from rc4 import RC4
import hashlib


def socks_handle(source, address):
    '''
        1. 打包接受到的数据
        2. websocket帧
        3. server 发出数据
    '''
    print('New connection from %s:%s' % address)

    # fileobj = source.makefile()
    # while True:
    #     line = fileobj.readline()
    #     if not line:
    #         print('client disconnection!')
    #         break
    #     fileobj.write(line)
    #     fileobj.flush()
    #     print('echo %r' % line)
    print('greenlet is %r', gevent.getcurrent())

    rfile = source.makefile('rb', -1)

    try:
        # pass 第一个报文
        # +-----+---------+---------+
        # | Ver | NMethods| Methods |
        # +-----+---------+---------+
        # | 1   | 1       |1 to 255 |
        # +-----+---------+---------+
        #  stage 0
        recvcount = source.recv(262)
        print("recv count: %r: %r " % (recvcount, type(recvcount)))

        #0x00: No Authentication required
        source.send(b'\x05\x00')

        ## 第二个报文
        # +-----------------------------------------+
        # | Ver CMD RSV    ATYP  DST.ADDR DST.PORT  |
        # +-----------------------------------------+
        # | 1    1   0x00  0x01
        # +-----------------------------------------+
        #  cmd:  0x01 connect
        #        0x02 bind
        #        0x03 udp associate
        #  ATYP: 0x01 Ipv4 address
        #        0x03 FQDN
        #        0x04 IPv6 address
        wsdata = ''
        data = rfile.read(4)
        print('second pack %r: %r' % (type(data), data))

        cmd = ord(data[1])  # CMD
        addrtype = ord(data[3])  # ADDR type 0x01 Ipv4 address

        wsdata = data[3]
        print(wsdata)

        if addrtype == 1:   # IPv4
            addrStr = rfile.read(4)
            addr = socket.inet_ntoa(addrStr)
            wsdata += addrStr
        elif addrtype == 3:  # Domain name
            domainlen = ord(rfile.read(1)[0])
            print('domain len %r' % domainlen)
            domain = rfile.read(domainlen)
            print('domain: %s \n' % domain)
            # addr = handle_dns(domain)
            addr = socket.inet_ntoa('\x00\x00\x00\x00')  # 16777343
            wsdata += chr(domainlen)
            wsdata += domain

        portstr = rfile.read(2)

        port = struct.unpack('>H', portstr)
        wsdata += portstr

        print('port: %r' % (port[0]))

        if cmd == 1:
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(addr) + struct.pack(">H", port[0])
            log("send replay %r" % reply)

            source.send(reply)
            log('Begin data, %s:%s' % (addr, port[0]))
            try:
                # gevent.monkey 阻塞
                ws = WebSocketClient('ws://sheltered-fjord-9488.herokuapp.com:80/', protocols=['binary'])
                ws.connect()
                log("connect remote websocket server!")

                encryptor = RC4(md5key('samzw'))

                log('send data %r:%r:%r' % (wsdata, type(wsdata), len(wsdata)))

                generator = encryptor.encrypter()
                out = ''
                for wc in wsdata:
                    out += chr((ord(wc) ^ generator.next()))

                ws.send(out, True)
                print('send encrypt data %s' % out)

                # li = gevent.spawn(incoming, source)
                # l2 = gevent.spawn(send_a_bunch, ws)

                # gevent.joinall([li, l2])
                l1 = gevent.spawn(handletcp, source, ws, generator)

                l2 = gevent.spawn(incoming, ws, source)
                gevent.joinall([l1, l2])

            except socket.error, (value, message):
                log('Conn refused, %s:%s:%s' % (addr, port[0], message))
                # Connection refused
                reply = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
                source.send(reply)
                # ws.close()
                raise
            except Exception, ex:
                print(Exception, ":", ex)
                raise
            finally:
                ws.close()
        else:
            print('Unsupported cmd: %r' % cmd)
            reply = b"\x05\0x07\0x00\0x01"
            source.send(reply)
    except socket.error, (value, message):
        log('socks_handle socket error, %s' % (message))
    finally:
        print('close socket: ---------------------------')
        source.close()


def handle_dns(domain):
    addr = gethostbyname(domain)
    return addr


def md5key(key):
    m = hashlib.md5(key.encode('utf-8'))
    return m.digest()


def handletcp(fr, to, generator):
    print('hanletcp...................')
    print('greenlet is %r' % gevent.getcurrent())
    try:
        while True:
            data = fr.recv(4096)
            if not data:
                break
            out = ''
            for c in data:
                out += chr((ord(c) ^ generator.next()))

            to.send(out, True)
            print('send http header.........')
    except socket.error, (value, message):
        log('socks_handle socket error, %s' % (message))
        raise

    print('handle tcp end!!!!!')


def incoming(wssock, source):
    print('incoming............. start!')
    encryptor = RC4(md5key('samzw'))
    generator = encryptor.encrypter()

    while True:
        m = wssock.receive()
        if m is not None:
            reply = ''
            for ch in str(m):
                reply += chr((ord(ch) ^ generator.next()))

            # print("%r" % reply)
            source.send(reply)
        else:
            break

    print('incoming............. end!')


def send_a_bunch(source):

    print('send_a_bunch .............')
    try:
        pass
        # log('send data %s' % data)
        # data = encryptor.encrypt(data)
        # wssock.send(data)
    except socket.error, (value, message):
        log('incoming socket error, %s' % (message))
        raise


def handle_tcp(sock):
    print("handle-tcp")
    fdset = [sock]
    data = []
    # sock.setblocking(0)
    # sock.setblocking(0)
    while True:
        print('circule.......')
        r, w, e = select.select(fdset, [], [], 20)  # 阻塞在这儿
        print('select.......')
        if sock in r:
            # if data.append(sock.recv(4096)) <= 0:
                # break
            vdata = sock.recv(4096)
            if not vdata:
                break
            data.append(vdata)

    print('recv data: %r', data)
    sock.send('HTTP/1.1 200 OK\nContent-Type: text/html\n\n')
    sock.send('<b>hello,world</b>')


def log(message, *args):
    message = message % args
    sys.stderr.write(message + '\n')


def main():
    server = StreamServer(('0.0.0.0', 1080), socks_handle)
    print('Starting server on port 1080')
    # log('Starting port forwarder %s:%s -> %s:%s', *(server.address[:2]))
    # gevent.signal(signal.SIGTERM, server.close)
    # gevent.signal(signal.SIGQUIT, server.close)
    # gevent.signal(signal.SIGINT, server.close)
    server.serve_forever()  # 同步
    # start() is an asynchronous function
    # server.start()
    # gevent.wait()

if __name__ == '__main__':
    main()
