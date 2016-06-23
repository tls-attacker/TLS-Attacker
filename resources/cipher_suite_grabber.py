#!/usr/bin/env python2

import sys
import re
import datetime
import hashlib
import optparse
import urllib2

# cheers Dirk :)
url = 'https://testssl.sh/mapping-rfc.txt'

for line in urllib2.urlopen(url):
    cipher = line.split()
    print cipher[1]+'(0'+cipher[0]+'),'
    
