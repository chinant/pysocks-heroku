#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-04-27 22:22:31
# @Version : 1.0

# socks5 package
# 第一个报文
# +-----+---------+---------+
# | Ver | NMethods| Methods |
# +-----+---------+---------+
# | 1   | 1       |1 to 255 |
# +-----+---------+---------+
#  stage 0
#  0x00: No Authentication required

## 第二个报文
# +----+-----+-------+------+----------+----------+
# |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+
#  cmd:  0x01 connect
#        0x02 bind
#        0x03 udp associate
#  ATYP: 0x01 Ipv4 address
#        0x03 FQDN  domain
#        0x04 IPv6 address


from __future__ import print_function

import struct
import sys
import gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
import signal
import gevent
from gevent.server import StreamServer
from gevent import select, socket
from gevent.socket import gethostbyname
from ws4py.client.geventclient import WebSocketClient
from rc4 import RC4
import hashlib
import argparse


class LocalSocks5Server(StreamServer):
    """support RC4 only for connections """
    def __init__(self, listener, dest, destport, method, password):
        StreamServer.__init__(self, listener)
        self.remotehost = "ws://" + dest + ":" + str(destport) + "/"
        log('dest: %s' % self.remotehost)
        self.method = method
        self.key = self.md5key(password)

    def handle(self, source, address):
        '''
            1. parse browser socks5 message
            2. establishes WebSocket connection to a remote server
            3. encrypt data using RC4
            4. forward with both the local and remote server
        '''
        log('New connection from %s:%s' % address)

        log('greenlet is %r', gevent.getcurrent())

        rfile = source.makefile('rb', -1)

        try:
            recvcount = source.recv(262)
            log("recv count: %r: %r " % (recvcount, type(recvcount)))

            source.send(b'\x05\x00')

            wsdata = ''
            data = rfile.read(4)
            log('second pack %r: %r' % (type(data), data))

            cmd = ord(data[1])  # CMD
            addrtype = ord(data[3])  # ADDR type 0x01 Ipv4 address

            wsdata = data[3]  # append type of address

            if addrtype == 1:   # IPv4
                addrStr = rfile.read(4)
                addr = socket.inet_ntoa(addrStr)
                wsdata += addrStr
            elif addrtype == 3:  # Domain name
                domainlen = ord(rfile.read(1)[0])
                domain = rfile.read(domainlen)
                log('domain len and name: %d %s' % (domainlen, domain))
                # addr = handle_dns(domain)
                addr = socket.inet_ntoa('\x00\x00\x00\x00')  # 16777343
                wsdata += chr(domainlen)
                wsdata += domain

            portstr = rfile.read(2)
            port = struct.unpack('>H', portstr)
            wsdata += portstr  # append port

            if cmd == 1:
                reply = b"\x05\x00\x00\x01" + socket.inet_aton(addr) + struct.pack(">H", port[0])
                log("send replay %r" % reply)

                source.send(reply)
                log('Begin data, %s:%s' % (addr, port[0]))

                ws = WebSocketClient(self.remotehost, protocols=['binary'])
                try:
                    # gevent.monkey 阻塞
                    ws.connect()
                    log("connect remote websocket server!")
                    log('send data %r:%r:%r' % (wsdata, type(wsdata), len(wsdata)))

                    encryptor = RC4(self.key)
                    generator = encryptor.encrypter()
                    out = ''
                    for wc in wsdata:
                        out += chr((ord(wc) ^ generator.next()))

                    # send socks5 message
                    ws.send(out, True)

                    l1 = gevent.spawn(self.forward, source, ws, generator)
                    l2 = gevent.spawn(self.incoming, ws, source)

                    gevent.joinall([l1, l2])

                except socket.error as e:
                    log('Conn refused, %s:%s:%s' % (addr, port[0], e.message))
                    # Connection refused
                    reply = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
                    source.send(reply)
                    raise e
                finally:
                    log('close websocket: ---------------------------')
                    ws.close()
            else:
                log('Unsupported cmd: %r' % cmd)
                reply = b"\x05\0x07\0x00\0x01"
                source.send(reply)
        except socket.error, (value, message):
            log('socks_handle socket error, %s' % (message))
        finally:
            log('close socket: ---------------------------')
            source.close()

    def close(self):
        if self.closed:
            sys.exit('listener socket is closed!')
        else:
            log('Closing listener socket')
            StreamServer.close(self)

    def md5key(self, key):
        m = hashlib.md5(key.encode('utf-8'))
        return m.digest()

    def handle_dns(self, domain):
        addr = gethostbyname(domain)
        return addr

    def forward(self, fr, to, generator):
        '''forward local data to remote server'''
        log('hanletcp...................')
        log('greenlet is %r' % gevent.getcurrent())

        try:
            while True:
                data = fr.recv(4096)
                if not data:
                    break
                out = ''
                for c in data:
                    out += chr((ord(c) ^ generator.next()))

                to.send(out, True)
        except socket.error as e:
            log('forward socket error, %s' % (e.message))
            # raise e

        print('handle tcp end!!!!!')

    def incoming(self, wssock, source):
        '''receive data from remote server'''
        log('incoming............. start!')
        encryptor = RC4(self.key)
        generator = encryptor.encrypter()
        try:
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
        except socket.error as e:
            log('incoming socket error, %s' % (e.message))
            # raise e

        log('incoming............. end!')


def handle_tcp(sock):
    print("handle-tcp")
    fdset = [sock]
    data = []
    # sock.setblocking(0)
    # sock.setblocking(0)
    while True:
        print('circule.......')
        r, w, e = select.select(fdset, [], [], 20)  # block in there
        print('select.......')
        if sock in r:
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


def usage():
    parser = argparse.ArgumentParser()
    # parser.add_argument('-u', )
    parser.add_argument("-b", "--localhost", metavar='', default='127.0.0.1', type=str, help="local bind adress (default: 127.0.0.1)")
    parser.add_argument("-l", "--localport", metavar='', default=1080, type=int, help="local bind port (default: 1080)")
    parser.add_argument("-s", "--remoteserver", metavar='', required=True, type=str, help="remote socks5 server")
    parser.add_argument("-r", "--remoteport", metavar='', required=True, type=int, help="remote socks5 port")
    parser.add_argument("-m", "--method", metavar='', required=True, type=str, help="encrypt method for communication data")
    parser.add_argument("-k", "--key", metavar='', required=True, type=str, help="encrypt password")
    # parser.add_argument('-b', '--localhost', dest='accumulate', action='store_const', const=sum, default=max, help='sum the integers (default: find the max)')
    args = parser.parse_args()
    parser.print_help()
    return args


def main():
    args = usage()
    # server = StreamServer((args.localhost, args.localport), socks_handle)
    listen = (args.localhost, args.localport)
    server = LocalSocks5Server(listen, args.remoteserver, args.remoteport, args.method, args.key)
    log('Starting server on port %s:%d' % (args.localhost, args.localport))
    gevent.signal(signal.SIGTERM, server.close)
    gevent.signal(signal.SIGQUIT, server.close)
    gevent.signal(signal.SIGINT, server.close)
    server.serve_forever()  # 同步 synchronization
    # start() is an asynchronous function
    # server.start()
    # gevent.wait()

if __name__ == '__main__':
    main()
