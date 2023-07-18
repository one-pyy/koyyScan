import json5
from typing import List,Tuple
input_data = [
    (22,'tcp','ssh/N'),
    (21,'tcp','ftp/2.2.2')  
]

data = {}
host = 'example.com'
data[host] = {}
data[host]['services'] = []

for port, proto, service in input_data:
    service_data = {'port': port, 'protocol': proto}
    if service is not None:
        service_data['service_app'] = [service]
    else:
        service_data['service_app'] = None
    
    data[host]['services'].append(service_data)

data[host]['deviceinfo'] = None 
data[host]['honeypot'] = None

json_data = json5.dumps(data, indent=4)
print(json_data)