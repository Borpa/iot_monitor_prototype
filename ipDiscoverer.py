import socket
import re

def getHostLocalIPV4():
    return socket.gethostbyname(socket.gethostname())

def getNetworkLocalV4():
    try:
        network = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.', getHostLocalIPV4())[0] + '0/24'
    except:
        network =  getHostLocalIPV4()
    return network

def getHostLocalIPV6():
    rawstr = str(socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6))
    ipv6 = re.findall('\w{4}\:\:\w{4}\:\w{4}\:\w{4}\:\w{4}', rawstr)[0]
    return ipv6

def getHostIPV6():
    rawstr = str(socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6))
    ipv6 = re.findall('\w{4}\:\:\w{4}\:\w{4}\:\w{4}\:\w{4}', rawstr)[1]
    return ipv6   

def getNetworkLocalV6():
    return ''

print(getHostLocalIPV6())