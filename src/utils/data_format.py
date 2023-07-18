import json
from typing import List,Tuple
from ..model import Finger,Service
from .components import *
from functools import wraps
'''
input_data = [
    (22,'tcp','ssh/N'),
    (21,'tcp','ftp/2.2.2')  
]

fingers:
{'1.1.1.1': {'services': [{'port': 22, 'protocol': 'tcp', 'service_app': ['ssh/N']}, {'port': 21, 'protocol': 'tcp', 'service_app': ['ftp/2.2.2']}], 'deviceinfo': None, 'honeypot': None}}
'''



def finger_filter(data:dict, comp_type: str):
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
      for apps in data:
          if apps.name in services:
              ans.append(apps)
      return ans
  
  return data


def finger_format(host: str,finger: Finger,status: int = 0):
    '''
    接收从finger_scan输出的主机和指纹信息,如果status为1将其格式化为单个json否则输出dict
    '''
    data = {}
    data[host] = {}
    data[host]['services'] = []

    for port, proto, service in finger:
        service_data = finger_filter({'port': port, 'protocol': proto},"protocol")
        if service is not None:
            service_data['service_app'] = finger_filter([service],"servise")
        else:
            service_data['service_app'] = None
        
        data[host]['services'].append(service_data)

    data[host]['deviceinfo'] = None 
    data[host]['honeypot'] = None
    if status == 1:
        json_data = json.dumps(data, indent=4)
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
