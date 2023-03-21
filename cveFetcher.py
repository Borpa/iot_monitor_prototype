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
source_cvedetails = 'https://www.cvedetails.com/cve/' #unavailable in RU
source_osv = 'https://osv.dev/vulnerability/'
source_mend = 'https://www.mend.io/vulnerability-database/'

def __validate_CVE_format(cve):
    return re.fullmatch('^CVE-\d{4}-\d{4,}$', cve)

def __get_HTML(source, cve):
    if (not __validate_CVE_format(cve)):
        raise Exception("Incorrect CVE format: ", cve)
    
    url = source + cve

    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"} #Mend blocks requests without headers
    response = requests.get(url, headers=headers)
    try:
        text = response.text
    except:
        raise Exception("Incorrect URL")
    return text

def get_CVE_info_from_NIST_JSON(cve):
    return json.dumps(get_CVE_info_from_NIST(cve), indent = 4)

def get_CVE_info_from_NIST(cve):
    html = __get_HTML(source_nist, cve)
    soup = BeautifulSoup(html, 'html.parser')

    vuln_desc = soup.find('p', attrs={'data-testid': 'vuln-description'}).getText()
    try:
        cvss_score = soup.find('a', attrs={'data-testid': "vuln-cvss3-panel-score"}).getText()
    except:
        cvss_score = "N/A"
    res = dict({"Description": vuln_desc, "CVSS": cvss_score})

    return res

def get_CVE_info_from_Mend(cve):
    html = __get_HTML(source_mend, cve)
    soup = BeautifulSoup(html, 'html.parser')

    vuln_desc = soup.findAll('div', attrs={'class': 'single-vuln-desc'})

    for vuln in vuln_desc:
        desc = vuln.find('p').getText()
        desc = desc.replace('\n', '')
        desc = desc.replace('  ', '')

        date = vuln.findAll('h4')[0]
        date = date.getText()
        date = date.replace('\n', '')
        date = date.replace('  ', '')

        lang = vuln.findAll('h4')[1]
        lang = lang.getText()
        lang = lang.replace('\n', '')
        lang = lang.replace('  ', '')

    try:
        cvss_score = soup.find('label', attrs={'class': "tooltipster"})['data-value']
    except:
        cvss_score = "N/A"
    res = dict({"Date": date, "Description": desc, "Language": lang, "CVSS": cvss_score})

    return res

def get_CVE_desc_from_CVEorg(cve):
    html = __get_HTML(source_cve, cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        vuln_desc = soup.find('p', attrs={'data-v-7b1e4942'}).getText()
    except:
        vuln_desc = 'N/A'
    return vuln_desc

def get_CVE_JSON(cve):
    rawstr = __get_HTML(source_cve_json, cve)
    return json.loads(rawstr)

def get_CVSS_score(cve):
    html = __get_HTML(source_cvedetails, cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        cvss = soup.find('div', attrs={'class':"cvssbox"}).getText()
    except:
        cvss = 'N/A'
    return cvss  

def get_CVE_details(cve):  
    html = __get_HTML(source_cvedetails, cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        cvss = soup.find('div', attrs={'class':"cvedetailssummary"}).getText()
    except:
        cvss = 'N/A'
    return cvss 

def get_CVE_urls(cve): 
    #html = __get_HTML(source_cvedetails, cve)
    #soup = BeautifulSoup(html, 'html.parser')
    #try:
    #    urls = soup.findAll('a', attrs={'title':"External url"})
    #except:
    #    urls = 'N/A'
    #return urls 

    html = __get_HTML(source_mend, cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        divs = soup.findAll('div', attrs={'class':"references"})
        urls = []
        for div in divs:
            urls.append(div.findAll('a'))
    except:
        urls = 'N/A'
    return urls 

def get_CVE_aliases(cve):
    html = __get_HTML(source_osv, cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        aliases= soup.findAll('ul', attrs={'class':"aliases"})
    except:
        aliases = 'N/A'
    return aliases

def get_CVE_report(cve):
    html = __get_HTML(source_mend, cve)
    soup = BeautifulSoup(html, 'html.parser')
    try:
        report= soup.findAll('table', attrs={'class':"table table-report"})
    except:
        report = 'N/A'
    return report

#async def __fetch_async(url):

def get_CVSS_score_list(cve_list): #TODO: make async with request limiter 
    result = []
    #for cve in cve_list
    return None

#print(get_CVE_info_from_NIST('CVE-2022-39952')['CVSS score'])

#https://www.cvedetails.com/cve/CVE-2023-26468/

#print(get_CVE_details('CVE-2019-0001'))


print(get_CVE_info_from_Mend('CVE-2023-1283'))