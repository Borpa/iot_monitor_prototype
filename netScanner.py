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

#scan_range = nm.scan(hosts = "",
#                     arguments="-6 -sV")

#scan_range = nm.scan(hosts="192.168.3.11",
#                     arguments="-sV -O")

#print(scan_range['scan'])
# --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv

#host_list = nm.scan(hosts="192.168.3.1/24",
#                     arguments="-sV -O -Pn")


def __load_scan_result_object(): 
    if (os.path.exists('./temp/scan_result.pkl')):
        scan_result = __load_object('./temp/scan_result.pkl')
        return scan_result
    else:
        return None
        nm = nmap.PortScanner()
        scan_range = nm.scan(hosts = "192.168.3.1 192.168.3.12",
                             arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
        scan_result = scan_range['scan']
        __save_object(scan_result, './temp/scan_result.pkl')
        return scan_result

#TODO: save as a JSON/dict: OSs, ports and running services, device (manufactureres)

def get_vuln_scan_result():
    if (os.path.exists('./temp/scan_result.pkl')):
        scan_result = __load_object('./temp/scan_result.pkl')
        return scan_result
    else:
        return None 

def get_host_scan_result():
    if (os.path.exists('./temp/hosts.pkl')):
        scan_result = __load_object('./temp/hosts.pkl')
        return scan_result
    else:
        return None    

def discover_hosts(network):
    #scan_result = __load_object('./temp/scan_result.pkl')
    #print(scan_result['192.168.3.12']['tcp'][135]) #-sU for UDP ports 
    #print(scan_result)
    #return scan_result

    nm = nmap.PortScanner()
    host_list = nm.scan(hosts=network,
                        arguments="-sV -sS -sU -O") #-oX <filename> -> XML format
    #nm.scan(hosts=network, arguments="-sV -O -oX")
    #xml = nmap.nm.get_nmap_last_output()
    __save_object(host_list, './temp/hosts.pkl')
    return host_list

#def discover_hosts(network, write_to_xml=False):
#    nm = nmap.PortScanner()
#    if (write_to_xml):
#        return None
#        #return nm.scan(hosts=network,
#        #                arguments="-sV -O -Pn -oX ./temp/host_list.xml")
#    else:
#        return discover_hosts(network)
#
def discover_v6_hosts():
    #nmap --script=ipv6-multicast-mld-list
    #ping - 6 ff02::1 
    return None

def scan_V6(hostS):
    return None

def scan(hostS):
    #nm = nmap.PortScanner()
    #scan_range = nm.scan(hosts = hostS,
    #                     arguments="-sV -sS -sU --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
    #scan_result = scan_range['scan']
    #__save_object(scan_result, './temp/scan_result.pkl')
    scan_result = __load_scan_result_object()

    #print(scan_range.all_hosts())
    #print(scan_result['192.168.3.1'].state())
    #print(scan_result['192.168.3.1'].all_protocols()) 
    #print(scan_result['192.168.3.1']['tcp'].keys())
    #print(scan_result['192.168.3.1']['tcp'][80])
    #print(scan_result['192.168.3.1'].tcp(80))

    #https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap
    #https://www.studytonight.com/network-programming-in-python/banner-grabbing
    keys = scan_result.keys()

    #print(keys)

    col = ['host', 'CVE', 'CVSS']

    df = pd.DataFrame(columns=col)
    df.index.name='id'
    df['CVE'] = df['CVE'].astype(object)

    i = 0

    for key in keys:
        raw_str = str(scan_result[key])

        cve_matches = re.findall('\[CVE-\d{4}-\d{4,5}', raw_str)
        formatted_cve_matches = []
        for match in cve_matches:
            match = match.replace('[','')
            formatted_cve_matches.append(match)
        formatted_cve_matches = np.unique(formatted_cve_matches)
        
        cvss_matches = re.findall('Score \d{1}.\d{1}', raw_str)
        cvss_scores = []
        for match in cvss_matches:
            match = match.split(' ')[1]
            cvss_scores.append(match)

        df.at[i, 'host'] = key
        df.at[i, 'CVE'] = formatted_cve_matches.tolist()
        df.at[i, 'CVSS'] = cvss_scores
        i+=1

    df[col].to_csv("./temp/scan.csv")
    df[col].to_json("./temp/scan.json")
    #__create_cve_cvss_db(df['CVE'].values)
    return df

#def __create_cve_cvss_db(cve_list):
#   cves = []
#   for cve in cve_list:
#       cves.extend(cve)
#   
#   cve_list = np.unique(cves)
#   cols = ['CVE', 'CVSS']
#   df = pd.DataFrame(columns=cols)
#   df.index.name='id'
#   i = 0 
#   for cve in cve_list:
#       df.at[i, 'CVE'] = cve
#       df.at[i, 'CVSS'] = fetcher.get_CVSS(cve)
#       i+=1
#
#   df.to_csv('./temp/cve-cvss-db.csv')

#matches = re.findall('\[CVE-\d{4}-\d{4}.*]', raw_str)

#https://www.cve.org/CVERecord?id=
#https://nvd.nist.gov/vuln/detail/CVE-

#print(scan('192.168.3.1'))
#discover_hosts('192.168.3.0/24')

#discover_hosts('192.168.11.49')

#scan_result = __load_object('./temp/hosts.pkl')

#print(scan_result['scan']['192.168.11.49']['osmatch'][0])


#print(scan_result['scan']['192.168.11.49']['tcp'][135]['state'])


#print(scan_result['scan']['192.168.11.49']['status'])

#scan result -> separate file for each host? or 1 big file
# table: host ports os vendor