#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-05-11 02:08:43
# @Author  : zhouwei (support@neatsoft.net)
# @Link    : http://neatsoft.net
# @Version : $Id$

import time


def test(n):
    m = 10
    vals = []
    keys = []
    for i in range(m):
        vals.append(i)
        keys.append('a%s' % i)
    d = None

    for i in range(n):
        d = dict(zip(keys, vals))
    return d

if __name__ == '__main__':
    st = time.time()
    print(test(1000000))
    print('use:', time.time() - st)
