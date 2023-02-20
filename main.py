#!/usr/bin/python3

#https://cve.mitre.org/data/downloads/

import nmap
import pandas as pd
import re
import numpy as np
import pickle
import os

def save_object(obj, filename):
    with open(filename, 'wb') as outp:
        pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)

def load_object(filename):
    with open(filename, 'rb') as inp:
        return pickle.load(inp)

#scan_range = nm.scan(hosts = "2400:2650:78c5:1200:608b:ea8f:a3f:aeda",
#                     arguments="-6 -sV")

#scan_range = nm.scan(hosts="192.168.3.11",
#                     arguments="-sV -O")

#print(scan_range['scan'])
# --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv

#host_list = nm.scan(hosts="192.168.3.1/24",
#                     arguments="-sV -O -Pn")

    
if (os.path.exists('scan_result.pkl')):
    scan_result = load_object('scan_result.pkl')
else:
    nm = nmap.PortScanner()
    scan_range = nm.scan(hosts = "192.168.3.1 192.168.3.12",
                         arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
    scan_result = scan_range['scan']
    save_object(scan_result, 'scan_result.pkl')

keys = scan_result.keys()

df = pd.DataFrame(columns=['host', 'CVE'])

i = 0

df['CVE'] = df['CVE'].astype(object)

for key in keys:
    raw_str = str(scan_result[key])
    matches = re.findall('\[CVE-\d{4}-\d{4}', raw_str)

    formatted_matches = []
    for match in matches:
        match = match.replace('[','')
        formatted_matches.append(match)
    
    formatted_matches = np.unique(formatted_matches)
    
    df.at[i, 'host'] = key
    df.at[i, 'CVE'] = formatted_matches.tolist()

    i+=1

print(df)
df.to_csv("scan.csv")
df.to_json("scan.json")

#matches = re.findall('\[CVE-\d{4}-\d{4}.*]', raw_str)

#https://www.cve.org/CVERecord?id=
#https://nvd.nist.gov/vuln/detail/CVE-