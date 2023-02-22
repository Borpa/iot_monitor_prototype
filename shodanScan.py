import sys
import os

from shodan import Shodan

api = Shodan('Yn665XldYsoEAn0MgAHJknB7azlWJAUY')

host = api.host('')

print("""
        IP: {}
        Organization: {}
        Operating System: {}
""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

# Print all banners
for item in host['data']:
        print("""
                Port: {}
                Banner: {}

        """.format(item['port'], item['data']))