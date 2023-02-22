import socket
import re

def get_host_local_IPV4():
    return socket.gethostbyname(socket.gethostname())

def get_network_local_IPV4():
    try:
        network = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.', get_host_local_IPV4())[0] + '0/24'
    except:
        network =  get_host_local_IPV4()
    return network

def get_host_local_IPV6():
    rawstr = str(socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6))
    ipv6 = re.findall('\w{4}\:\:\w{4}\:\w{4}\:\w{4}\:\w{4}', rawstr)[0]
    return ipv6

def get_host_IPV6():
    rawstr = str(socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6))
    ipv6 = re.findall('\w{4}\:\w{4}\:\w{4}\:\w{4}\:\w{4}\:\w{4}\:\w{4}\:\w{4}', rawstr)[1]
    return ipv6

def get_network_local_IPV6():
    return None

print(get_host_IPV6())