import pandas as pd
import numpy as np
import cveFetcher as fetcher
import os
import ast

import asyncio
import aiohttp
import time
from aiolimiter import AsyncLimiter

def createDb():
    if (os.path.exists('./temp/cve-cvss-db.csv')):
        __update_db()
    else:
        __create_cve_cvss_db()

def updateDb():
    if (os.path.exists('./temp/cve-cvss-db.csv')):
        __update_db()
    else:
        __create_cve_cvss_db()

def __create_cve_cvss_db():
   if (not os.path.exists('./temp/scan.csv')): 
       raise Exception('Scan results were not detected')
   df = pd.read_csv('./temp/scan.csv')
   cve_list = df['CVE'].values
   cves = []
   for cve in cve_list:
       #cves.extend(cve.strip('][').split(', '))
       cves.extend(ast.literal_eval(cve))
   
   cves = np.unique(cves)
   #return len(cves)
   cols = ['CVE', 'CVSS']
   df = pd.DataFrame(columns=cols)
   df.index.name='id'
   i = 0 
   for cve in cves:
   #TODO: make an async method with request limits
       df.at[i, 'CVE'] = cve
       #df.at[i, 'CVSS'] = fetcher.get_CVSS_score(cve)
       df.at[i, 'CVSS'] = fetcher.get_CVE_info_from_NIST(cve)['CVSS']
       i+=1

   df.to_csv('./temp/cve-cvss-db.csv')

def __update_db(cve):
    if (not os.path.exists('./temp/scan.csv')): 
       raise Exception('Scan results were not detected')
    df = pd.read_csv('./temp/scan.csv')
    cve_list = df['CVE'].values
    cves = []
    for cve in cve_list:
        cves.extend(ast.literal_eval(cve))
    cves = np.unique(cves)

    df_cve = pd.read_csv('./temp/cve-cvss-db.csv')
    i = len(df_cve)
    for cve in cves:
        if cve in df_cve.values: continue
        df_cve.at[i, 'CVE'] = cve
        #df_cve.at[i, 'CVSS'] = fetcher.get_CVSS_score(cve)
        df_cve.at[i, 'CVSS'] = fetcher.get_CVE_info_from_NIST(cve)['CVSS']
        i+=1
        
    df_cve.to_csv('./temp/cve-cvss-db.csv', mode='a', header=False)
       

#createDb()