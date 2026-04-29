#!/usr/bin/python3
import hashlib
from sys import argv

c = 0
chunksize = 131072
md = hashlib.sha1()
with open(argv[1], 'rb') as istr:
    while True:
        chunk = istr.read(chunksize)
        if not chunk:
            break
        md.update(chunk)
        print(c, c + len(chunk), md.hexdigest())
        c += len(chunk)
