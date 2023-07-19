import json
from typing import List,Tuple
from ..model import Finger,Service,Device,Honeypot
from .components import *
from functools import wraps
import re
'''
input_data = [
    (22,'tcp','ssh/N'),
    (21,'tcp','ftp/2.2.2')  
]

fingers:
{'1.1.1.1': {'services': [{'port': 22, 'protocol': 'tcp', 'service_app': ['ssh/N']}, {'port': 21, 'protocol': 'tcp', 'service_app': ['ftp/2.2.2']}], 'deviceinfo': None, 'honeypot': None}}
'''



def finger_filter(data:dict, comp_type: str,script: dict = None):
  '''
  过滤不在列表中的service和protocol,comp_type指定为service或protocol
  '''
  services = get_servises()
  protocols = get_protocols()
  if comp_type == "protocol":
      protocol = data['protocol'] if data['protocol'] in protocols else None
      data['protocol'] = protocol
  elif comp_type == "servise":
      ans = list()
      try:
        for serve in services:
            if re.search(serve,data['service']['product'],re.IGNORECASE):
                ans.append(str(Service(serve,data['service']['version'])))
            
      except:
        pass
      return ans
  
  return data


def finger_format(host: str,finger: Finger,devices: List[Device] = None ,honeypot: Honeypot = None,status: int = 0):
    '''
    接收从finger_scan输出的主机和指纹信息,如果status为1将其格式化为单个json否则输出dict
    '''
    data = {}
    data[host] = {}
    data[host]['services'] = []

    for port, proto, service, script in finger:
        service_data = finger_filter({'port': port, 'protocol': proto},"protocol")
        if service is not None :
            service_data['service_app'] = finger_filter([service],"servise",script) if len(finger_filter([service],"servise"))>0 else None
        else:
            service_data['service_app'] = None
        
        data[host]['services'].append(service_data)

    data[host]['deviceinfo'] = devices 
    data[host]['honeypot'] = honeypot
    if status == 1:
        json_data = json.dumps(data, indent=2)
        return json_data
    else:
        return data


def json_merge(*jsons) -> json:
    '''合并多个json'''
    merged_data = {}
    for json_str in jsons:
        data = json.loads(json_str)
        merged_data.update(data)
    return json.dumps(merged_data)

def finger_merge(*fingers: dict) -> dict:
    '''
    合并多个dict
    '''
    merged_data = {}
    for finger in fingers:
        merged_data.update(finger)
    return merged_data
