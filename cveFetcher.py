#!/usr/bin/python3

import re
import requests
import json
from bs4 import BeautifulSoup

source_cve = 'https://www.cve.org/CVERecord?id='
source_nist = 'https://nvd.nist.gov/vuln/detail/'

def __getHTML(url):
    response = requests.get(url)
    return response.text

def __validateCVEFormat(cve):
    return re.fullmatch('^CVE-\d{4}-\d{4}$', cve)

def getCVEInfoFromNIST(cve):
    if (not __validateCVEFormat(cve)):
        return ''
    
    html = __getHTML(source_nist + cve)
    soup = BeautifulSoup(html, 'html.parser')

    vuln_desc = soup.find('p', attrs={'data-testid': 'vuln-description'}).getText()
    try:
        cvss_score = soup.find('a', attrs={'data-testid': "vuln-cvss3-panel-score"}).getText()
    except:
        cvss_score = "N/A"
    res = dict({"Description": vuln_desc, "CVSS score": cvss_score})

    return json.dumps(res, indent = 4)

def getCVEInfoFromCVEorg(cve):
    if (not __validateCVEFormat(cve)):
        return ''
    html = __getHTML(source_cve + cve)
    soup = BeautifulSoup(html, 'html.parser')
