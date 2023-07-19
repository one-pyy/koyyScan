import nmap,json,xmltodict
import sys
import traceback
from typing import *

from objprint import op
from pitricks.utils import make_parent_top

make_parent_top(2)

from ..model import Ip, Port, Protocal, Service, Finger, Version


def finger_scan(ip: Ip, ports: Iterable[Port]) -> List[Finger]:
  '''
  根据已存活主机、端口列表探测指纹信息,返回当前主机的指纹信息列表
  '''
  try:
    #创建端口扫描对象
    nm = nmap.PortScanner()
  except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(0)
  except:
    traceback.print_exc()
    sys.exit(0)

  try:
    #调用nmap扫描方法
    nm.scan(
        ip,
        ports=','.join(map(str, ports)),
        arguments=
        f'-v -sS -Pn -sV -A -T4 --script=banner,ssl-cert,http-title,http-headers -oN ./result/_nmap/{ip}_nm')
  except Exception as e:
    traceback.print_exc()
    raise
  _default_output(nm)
  devices_check(ip, nm)
  

  ans = []
  # 输出TCP\UDP协议及端口状态
  for proto in nm[ip].all_protocols():
    #获取协议的所有扫描端口
    lport = nm[ip][proto].keys()
    #遍历端口及输出端口与状态
    for port in lport:
      service = Service(nm[ip][proto][port]["product"].lower(),
                        Version(nm[ip][proto][port]["version"]))
      script = nm[ip][proto][port]['script'] if 'script' in nm[ip][proto][
          port] else None
      ans.append((port, nm[ip][proto][port]["name"], service, script))
  
  honeypot_check(ans)
  return ans

def devices_check(ip:Ip,nm: nmap.PortScanner):
  '''检测设备信息'''
  
  try:
    headers = nm[ip]['tcp'][80]['script']['http-headers']
    if 'Server: Synology' in headers:
      print(f"{ip} is Synology NAS")
    elif 'Server: pfSense' in headers:
      print(f"{ip} is pfSense Firewall")
  except (KeyError, IndexError):
    print(f"{ip} no http-headers")
    # sys.exit(0)
  except:
    traceback.print_exc()
    sys.exit(0)

  try:
    os_match = nm[ip]['osmatch'][0]
    if os_match and os_match['name'] == 'Cisco IOS':
      print(f"{ip} is Cisco Router")
  except IndexError:
    print(f"{ip} no osmatch")
  except:
    traceback.print_exc()
    sys.exit(0)

  try:
    title = nm[ip]['tcp'][80]['script']['http-title']
    if 'Hikvision' in title:
      print(f"{ip} may be Hikvision camera")
  except (KeyError, IndexError):
    print(f"{ip} no http-title")
    # sys.exit(0)
  except:
    traceback.print_exc()
    sys.exit(0)


def honeypot_check(finger: List[Finger]):
  pass

def _default_output(_nm: nmap.PortScanner()):
  order_dict = xmltodict.parse(_nm.get_nmap_last_output())
  host = _nm.all_hosts()[0]
  with open(f'./result/json/{host}_nm.json','w') as f:
    f.write(json.dumps(order_dict,indent=4))
    print(f"Host:{host} Saved.")
    
    

if __name__ == '__main__':
  op(finger_scan('113.30.191.68', [2222]))
  # op(finger_scan(
  #   '211.22.90.152', {49152, 8000, 554, 80, 9010}))
