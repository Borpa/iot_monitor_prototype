#!/usr/bin/python3

# https://cve.mitre.org/data/downloads/

import nmap
import pandas as pd
import re
import numpy as np
import pickle
import os
import cve_cvss_dbCreator as dbcreator


def __save_object(obj, filename):
    with open(filename, 'wb') as outp:
        pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)


def __load_object(filename):
    with open(filename, 'rb') as inp:
        return pickle.load(inp)


def __load_scan_result_object():
    if (os.path.exists('./temp/scan_result.pkl')):
        scan_result = __load_object('./temp/scan_result.pkl')
        return scan_result
    else:
        return None
        nm = nmap.PortScanner()
        scan_range = nm.scan(hosts="192.168.3.1 192.168.3.12",
                             arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
        scan_result = scan_range['scan']
        __save_object(scan_result, './temp/scan_result.pkl')
        return scan_result

# TODO: save as a JSON/dict: OSs, ports and running services, device (vendors)


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


def discover_hosts_placeholder(network, args="-sV -O"):
    scan_result = __load_object('./temp/scan_result.pkl')
    return scan_result


def discover_hosts(network, args="-sV -O"):
    nm = nmap.PortScanner()
    args += '-sS -sU'
    host_list = nm.scan(hosts=network,
                        arguments=args)  # -oX <filename> -> XML format
    __save_object(host_list, './temp/hosts.pkl')
    # return host_list


def discover_v6_hosts():
    # nmap --script=ipv6-multicast-mld-list
    # ping - 6 ff02::1
    return None


def scan_V6(hostS):
    return None


def vuln_scan(hostS, args='-O'):
    nm = nmap.PortScanner()
    args += '-sV -sS -sU'
    scan_range = nm.scan(hosts=hostS,
                         arguments="-sV -sS -sU -O --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
    scan_result = scan_range['scan']
    __save_object(scan_result, './temp/scan_result.pkl')
    hosts = scan_result.keys()
    col = ['host', 'CVE', 'CVSS']

    df = pd.DataFrame(columns=col)
    df.index.name = 'id'
    df['CVE'] = df['CVE'].astype(object)

    i = 0
    for host in hosts:
        raw_str = str(scan_result[host])

        cve_matches = re.findall('\[CVE-\d{4}-\d{4,5}', raw_str)
        formatted_cve_matches = []
        for match in cve_matches:
            match = match.replace('[', '')
            formatted_cve_matches.append(match)
        formatted_cve_matches = np.unique(formatted_cve_matches)

        cvss_matches = re.findall('Score \d{1}.\d{1}', raw_str)
        cvss_scores = []
        for match in cvss_matches:
            match = match.split(' ')[1]
            cvss_scores.append(match)

        df.at[i, 'host'] = host
        df.at[i, 'CVE'] = formatted_cve_matches.tolist()
        df.at[i, 'CVSS'] = cvss_scores
        i += 1

    df[col].to_csv("./temp/scan.csv")
    df[col].to_json("./temp/scan.json")
    dbcreator.updateDb()
    # return df


def scan_placeholder(hostS, args):
    # nm = nmap.PortScanner()
    # scan_range = nm.scan(hosts = hostS,
    #                     arguments="-sV --script vulscan/vulscan.nse --script-args vulscandb=allitems.csv")
    # scan_result = scan_range['scan']
    # __save_object(scan_result, './temp/scan_result.pkl')
    scan_result = __load_scan_result_object()

    # print(scan_range.all_hosts())
    # print(scan_result['192.168.3.1'].state())
    # print(scan_result['192.168.3.1'].all_protocols())
    # print(scan_result['192.168.3.1']['tcp'].keys())
    # print(scan_result['192.168.3.1']['tcp'][80])
    # print(scan_result['192.168.3.1'].tcp(80))

    # https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap
    # https://www.studytonight.com/network-programming-in-python/banner-grabbing
    keys = scan_result.keys()

    # print(keys)

    col = ['host', 'CVE', 'CVSS']

    df = pd.DataFrame(columns=col)
    df.index.name = 'id'
    df['CVE'] = df['CVE'].astype(object)

    i = 0

    for key in keys:
        raw_str = str(scan_result[key])

        cve_matches = re.findall('\[CVE-\d{4}-\d{4,5}', raw_str)
        formatted_cve_matches = []
        for match in cve_matches:
            match = match.replace('[', '')
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
        i += 1

    df[col].to_csv("./temp/scan.csv")
    df[col].to_json("./temp/scan.json")
    # __create_cve_cvss_db(df['CVE'].values)
    return df


# print(scan('192.168.3.1'))
# discover_hosts('192.168.3.0/24')

# discover_hosts('192.168.11.49')

# scan_result = __load_object('./temp/hosts.pkl')

# print(scan_result['scan']['192.168.11.49']['osmatch'][0])


# print(scan_result['scan']['192.168.11.49']['tcp'][135]['state'])


# print(scan_result['scan']['192.168.11.49']['status'])

# scan result -> separate file for each host? or 1 big file
# table: host ports os vendor

# scan = get_host_scan_result()
# print(scan['scan']['192.168.11.49']['osmatch'])
