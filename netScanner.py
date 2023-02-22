#!/usr/bin/python3

#https://cve.mitre.org/data/downloads/

import nmap
import pandas as pd
import re
import numpy as np
import pickle
import os

def __save_object(obj, filename):
    with open(filename, 'wb') as outp:
        pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)

def __load_object(filename):
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


def __load_scan_resul_object(): 
    if (os.path.exists('./temp/scan_result.pkl')):
        scan_result = __load_object('./temp/scan_result.pkl')
        return scan_result
    else:
        nm = nmap.PortScanner()
        scan_range = nm.scan(hosts = "192.168.3.1 192.168.3.12",
                             arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
        scan_result = scan_range['scan']
        __save_object(scan_result, './temp/scan_result.pkl')
        return scan_result

def discover_hosts(network):
    nm = nmap.PortScanner()
    host_list = nm.scan(hosts=network,
                        arguments="-sV -O -Pn") #-oX <filename> -> XML format
    return host_list

def discover_hosts(network, write_to_xml=False):
    nm = nmap.PortScanner()
    if (write_to_xml):
        return nm.scan(hosts=network,
                        arguments="-sV -O -Pn -oX ./temp/host_list.xml")
    else:
        return discover_hosts(network)

def discover_v6_hosts():
    #nmap --script=ipv6-multicast-mld-list
    #ping - 6 ff02::1 
    return None

def scan_V6(hostS):
    return None

def scan(hostS):
    #nm = nmap.PortScanner()
    #scan_range = nm.scan(hosts = hostS,
    #                     arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
    #scan_result = scan_range['scan']

    scan_result = __load_scan_resul_object()

    keys = scan_result.keys()

    df = pd.DataFrame(columns=['host', 'CVE', 'CVSS'])
    df['CVE'] = df['CVE'].astype(object)

    i = 0

    for key in keys:
        raw_str = str(scan_result[key])

        cve_matches = re.findall('\[CVE-\d{4}-\d{4}', raw_str)
        formatted_cve_matches = []
        for match in cve_matches:
            match = match.replace('[','')
            formatted_cve_matches.append(match)
        formatted_cve_matches = np.unique(formatted_cve_matches)
        
        cvss_matches = re.findall('Base Score \d{1}.\d{1}', raw_str)
        cvss_scores = []
        for match in cvss_matches:
            match = match.split(' ')[2]
            cvss_scores.append(match)

        df.at[i, 'host'] = key
        df.at[i, 'CVE'] = formatted_cve_matches.tolist()
        df.at[i, 'CVSS'] = cvss_scores

        i+=1

    df.to_csv("./temp/scan.csv")
    df.to_json("./temp/scan.json")
    return df

#matches = re.findall('\[CVE-\d{4}-\d{4}.*]', raw_str)

#https://www.cve.org/CVERecord?id=
#https://nvd.nist.gov/vuln/detail/CVE-

print(scan('192.168.3.1'))