#!/usr/bin/python3

import re
import requests
import json
from bs4 import BeautifulSoup

import asyncio
import aiohttp
import time
from aiolimiter import AsyncLimiter

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
    return re.fullmatch('^CVE-\d{4}-\d{4,}$', cve)

def get_CVE_info_from_NIST_JSON(cve):
    return json.dumps(get_CVE_info_from_NIST(cve), indent = 4)

def get_CVE_info_from_NIST(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format: ", cve)
    
    html = __get_HTML(source_nist + cve)
    soup = BeautifulSoup(html, 'html.parser')

    vuln_desc = soup.find('p', attrs={'data-testid': 'vuln-description'}).getText()
    try:
        cvss_score = soup.find('a', attrs={'data-testid': "vuln-cvss3-panel-score"}).getText()
    except:
        cvss_score = "N/A"
    res = dict({"Description": vuln_desc, "CVSS score": cvss_score})

    return res

def get_CVE_desc_from_CVEorg(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format: ", cve)
    
    html = __get_HTML(source_cve + cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        vuln_desc = soup.find('p', attrs={'data-v-7b1e4942'}).getText()
    except:
        vuln_desc = None
    return vuln_desc

def get_CVE_JSON(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format")
    
    rawstr = __get_HTML(source_cve_json + cve)
    return json.loads(rawstr)

def get_CVSS_score(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format: ", cve)   
    html = __get_HTML('https://www.cvedetails.com/cve/' + cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        cvss = soup.find('div', attrs={'class':"cvssbox"}).getText()
    except:
        cvss = 'N/A'
    return cvss  

def get_CVE_details(cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format: ", cve)   
    html = __get_HTML('https://www.cvedetails.com/cve/' + cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        cvss = soup.find('div', attrs={'class':"cvedetailssummary"}).getText()
    except:
        cvss = 'N/A'
    return cvss   

#async def __fetch_async(url):

def get_CVSS_score_list(cve_list): #TODO: make async with request limiter 
    result = []
    #for cve in cve_list
    return None

#print(get_CVE_info_from_NIST('CVE-2022-39952')['CVSS score'])

#https://www.cvedetails.com/cve/CVE-2023-26468/

#print(get_CVE_details('CVE-2019-0001'))