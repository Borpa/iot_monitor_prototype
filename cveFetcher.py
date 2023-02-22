#!/usr/bin/python3

import re
import requests
import json
from bs4 import BeautifulSoup

source_cve = 'https://www.cve.org/CVERecord?id='
source_cve_json = 'https://cveawg.mitre.org/api/cve/'
source_nist = 'https://nvd.nist.gov/vuln/detail/'

def __get_HTML(url):
    response = requests.get(url)
    try:
        text = response.text
    except:
        raise Exception("Incorrect URL")
    return text

def __validate_CVE_format(cve):
    return re.fullmatch('^CVE-\d{4}-\d{4}$', cve)

def get_CVE_info_JSON_from_NIST(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format")
    
    html = __get_HTML(source_nist + cve)
    soup = BeautifulSoup(html, 'html.parser')

    vuln_desc = soup.find('p', attrs={'data-testid': 'vuln-description'}).getText()
    try:
        cvss_score = soup.find('a', attrs={'data-testid': "vuln-cvss3-panel-score"}).getText()
    except:
        cvss_score = "N/A"
    res = dict({"Description": vuln_desc, "CVSS score": cvss_score})

    return json.dumps(res, indent = 4)

def get_CVE_desc_from_CVEorg(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format")
    
    html = __get_HTML(source_cve + cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        vuln_desc = soup.find('p', attrs={'data-v-7b1e4942'}).getText()
    except:
        vuln_desc = None
    print(vuln_desc)

def get_CVE_JSON(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format")
    
    rawstr = __get_HTML(source_cve_json + cve)
    return json.loads(rawstr)

