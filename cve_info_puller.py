#!/usr/bin/python3

import sys
import re
from bs4 import BeautifulSoup

cve = sys.argv

if (type(cve) != type(str) or re.fullmatch('^CVE-\d{4}-\d{4}$', cve)):
    print(-1)

#https://www.cve.org/CVERecord?id=
#https://nvd.nist.gov/vuln/detail/CVE-
