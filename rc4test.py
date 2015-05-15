#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-05-08 03:01:28
# @Version : $Id$

from __future__ import print_function
import unittest
from rc4 import RC4
import hashlib


def md5key(key):
    m = hashlib.md5(key.encode('utf-8'))
    return m.digest()


class RCTestCase(unittest.TestCase):

    def test_plain_text(self):
        plain_text = 'this is proto samples'
        rc4 = RC4('samzw')
        data = rc4.encrypt(plain_text)
        data = rc4.decrypt(data)
        self.assertEqual(plain_text, data)

    def test_hex_text(self):
        rc4 = RC4(md5key('password'))
        hex_text = '\xfe\x85\x8f\xebjg\x81\xd0f\x9b\x98\x83'
        data = rc4.encrypt(hex_text)
        for x in data:
            print("%r" % x)
        data = rc4.decrypt(data)
        self.assertEqual(hex_text, data)

    def test_file(self):
        w = open('../README.md', 'w')
        rc4 = RC4('password')

        generator = rc4.encrypter()
        out = ''
        with open('README.md') as f:
            for line in f:
                for c in line:
                    out += chr((ord(c) ^ generator.next()))
            w.write(out)
            out = ''

        w.close()

    def test_file2(self):
        rc4 = RC4('password')
        generator = rc4.encrypter()
        w = open('../Python.pdf', 'w')
        fobj = open('../Python1.pdf')

        out = ''
        while True:
            chunk_data = fobj.read(1024*1024)
            if not chunk_data:
                break
            for c in chunk_data:
                out += chr((ord(c) ^ generator.next()))

            w.write(out)
            out = ''

        fobj.close()
        w.close()

        def test_decrypt_file():
            pass


if __name__ == '__main__':
    unittest.main()
