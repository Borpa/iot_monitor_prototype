#!/usr/bin/python3

import sys
import re
import requests
from bs4 import BeautifulSoup

def getHTML(url):
    response = requests.get(url)
    return response.text

if (len(sys.argv) != 2):
    sys.exit("Incorrect input")

cve = sys.argv[1]

if (not re.fullmatch('^CVE-\d{4}-\d{4}$', cve)):
    sys.exit("Incorrect input")

print(cve)

source_1 = 'https://www.cve.org/CVERecord?id='
source_2 = 'https://nvd.nist.gov/vuln/detail/'

html = getHTML(source_2 + cve)

soup = BeautifulSoup(html, 'html.parser')

vuln_desc = soup.find('p', attrs={'data-testid': 'vuln-description'}).getText()
cvss_score = soup.find('a', attrs={'data-testid': "vuln-cvss3-panel-score"}).getText()

print("Description: ", vuln_desc)
print("CVSS score: ", cvss_score)
