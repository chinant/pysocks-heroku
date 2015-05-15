#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-04-24 22:59:46
# @Version : $Id$


class RC4(object):
    """docstring for RC4"""
    def __init__(self, key):
        super(RC4, self).__init__()
        # m = md5.new()
        # m.update(key)
        self.key = key  # m.digest()

    def __ksa__(self, table):
        '''function kas for pseudorandom number'''
        j = 0
        for index_table, item in enumerate(table):
            j = (j + item + ord(self.key[index_table % len(self.key)])) % 256
            table[index_table], table[j] = table[j], table[index_table]
        #print table

    def encrypt(self, plain):
        '''rc4 encrypt'''
        table = list(range(256))
        self.__ksa__(table)
        i = 0
        j = 0
        k = []
        for text in plain:
            i = (i + 1) % 256
            j = (j + table[i]) % 256
            table[i], table[j] = table[j], table[i]
            #k[index] = ord(text) ^ table[(table[i] + table[j]) % 256]
            k.append(chr(ord(text) ^ table[(table[i] + table[j]) % 256]))
        # print k
        return ''.join(k)

    def decrypt(self, plain):
        '''rc4 decrypt'''
        out = self.encrypt(plain)
        return ''.join(out)

    def encrypter(self):
        '''generator for big data or big file '''
        table = range(256)
        self.__ksa__(table)
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + table[i]) % 256
            table[i], table[j] = table[j], table[i]
            k = table[(table[i] + table[j]) % 256]
            yield k


def main():
    '''main function'''
    plain_text = 'this is proto samples'
    print('encrypt before: %s' % plain_text)
    rc4 = RC4('samzw')
    data = rc4.encrypt(plain_text)
    data = rc4.decrypt(data)
    print('decrypt after: %s' % data)

    generator = rc4.encrypter()

    for c in plain_text:
        print("%02X" % (ord(c) ^ generator.next()))


if __name__ == '__main__':
    main()
