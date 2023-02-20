#!/usr/bin/python3

#https://cve.mitre.org/data/downloads/

import nmap
import json
import pandas as pd

nm = nmap.PortScanner()
#scan_range = nm.scan(hosts = "2400:2650:78c5:1200:608b:ea8f:a3f:aeda",
#                     arguments="-6 -sV")

scan_range = nm.scan(hosts="192.168.3.11",
                     arguments="-sV -O")
#print(scan_range['scan'])
# --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv

#host_list = nm.scan(hosts="192.168.3.1/24",
#                     arguments="-sV -O -Pn")

scan_range = nm.scan(hosts = "192.168.3.12",
                     arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")

scan_result = scan_range['scan']



#jsondata = json.dumps(scan_range['scan'], indent = 10) 
#print(jsondata)

#df = pd.read_csv(nm.csv())
#df = pd.read_json(jsondata)
#df.to_csv("scan.csv")
#df.to_json("scan.json")

#https://www.cve.org/CVERecord?id=
#https://nvd.nist.gov/vuln/detail/CVE-