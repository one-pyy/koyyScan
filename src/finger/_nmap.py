from ..model import Ip, Port, Protocal, Service, Finger, Version, Device, Honeypot
import nmap
import json
import xmltodict
import sys
import traceback
from typing import *
import re
from objprint import op
from pitricks.utils import make_parent_top

make_parent_top(2)

from ..model import Ip, Port, Protocal, Service, Finger, Version, Honeypot


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
        arguments=f'-v -sS -Pn -sV -A -T4 --script=banner,ssh-hostkey,tls-nextprotoneg,ssl-enum-ciphers,http-favicon,http-title,http-traceroute,telnet-ntlm-info -oN ./result/_nmap/{ip}_nm')
  except Exception as e:
    traceback.print_exc()
    raise

  _default_output(nm) 
  dc = devices_check(ip, nm)
  print(dc.get_result())

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

  return ans


class devices_check:
  def __init__(self, ip: Ip, nm: nmap.PortScanner) -> None:
    super().__init__()
    self.ip = ip
    self.nm = nm
    # self._type = _type
    self.result = dict()
  
  def get_result(self):
    self.parse_result()
    return self.result
  
  def parse_result(self):
    host = next(iter(self.nm.all_hosts()))

    if self.check_pfsense(host):
        self.result['firewall'] = 'pfsense'

    if self.check_hikvision(host):
        self.result['Webcam'] = 'Hikvision'

    if self.check_dahua(host) or self.check_cisco(host):
        self.result['switch'] = []
        if self.check_dahua(host):
            self.result['switch'].append('dahua')
        if self.check_cisco(host):
            self.result['switch'].append('cisco')

    if self.check_synology(host):
        self.result['Nas'] = 'synology'

  def check_pfsense(self, ip):
    '''pfSense检测'''
    try:
      if 'Server: pfSense' in self.nm[ip]['tcp'][80]['script']['http-headers']:
        return True
      elif 'FreeBSD' in str(self.nm[ip]['osmatch'][0]['name']):
        return True
    except (KeyError, IndexError):
      print(f"{ip} no correct script")
    except:
      traceback.print_exc()
      sys.exit(0)
    return False

  def check_hikvision(self, ip):
    # 检查Hikvision特征
    try:
      if 'Hikvision IPCam control port' in self.nm[ip]['tcp'][8000]['product']:
         return True
      elif 'Hikvision' in str(self.nm[ip]['osmatch'][0]['name']):
         return True
      elif 'Hikvision' in self.nm[ip]['tcp'][80]['script']['http-title']:
         return True
    except (KeyError, IndexError):
      print(f"{ip} no correct script")
    except:
      traceback.print_exc()
      sys.exit(0)
    return False

  def check_dahua(self, ip):
    # 检查Dahua特征
    try:
      if 'Linux' in self.nm[ip]['osmatch'][0]['name']:
        pass
      else:
        return False
      if re.search(r'Dahua',str(self.nm[ip]['tcp'][8000]),re.IGNORECASE):
        return True
      elif re.search(r'Dahua',str(self.nm[ip]['tcp'][80]['script']['http-favicon']),re.IGNORECASE):
        return True
      elif re.search(r'Dahua',str(self.nm[ip]['tcp'][80]['script']['http-title']),re.IGNORECASE):
        return True
    except (KeyError, IndexError):
      print(f"{ip} no correct script")
    except:
      traceback.print_exc()
      sys.exit(0)
    return False

  def check_cisco(self, ip):
      # 检查Cisco特征
    try:
      if 'IOS' in str(self.nm[ip]['osmatch'][0]) and 23 in self.nm[ip]['tcp'] and 22 in self.nm[ip]['tcp']:
        pass
      else:
        return False
      if re.search(r'Cisco', str(self.nm[ip]['tcp'][23]['script']['banner']),re.IGNORECASE):
        return True
      elif re.search(r'Cisco', str(self.nm[ip]['tcp'][80]['script']['http-title']),re.IGNORECASE):
        return True
    except (KeyError, IndexError):
      print(f"{ip} no correct script")
    except:
      traceback.print_exc()
      sys.exit(0)
    return False

  def check_synology(self, ip):
      # 检查Synology特征
    try:
      if 'Linux' in self.nm[ip]['osmatch'][0]['name'] and 5000 in self.nm[ip]['tcp']:
        pass
      else:
        return False
      if re.search(r'Synology',str(self.nm[ip]['tcp'][5000]['banner']),re.IGNORECASE):
        return True
      elif re.search(r'Synology',str(self.nm[ip]['tcp'][80]['script']['http-title'] ),re.IGNORECASE):
        return True
    except (KeyError, IndexError):
      print(f"{ip} no correct script")
    except:
      traceback.print_exc()
      sys.exit(0)
    return False

  def honeypot_check(finger: List[Finger]):
    pass

def honeypot_check(fingers: List[Finger]):
  ans = []
  for f in fingers:
    if f[0]=='2222' and f[3]['banner'] == "SSH-2.0-OpenSSH_5.1p1 Debian-5":
      ans.append(Honeypot(2222, "Kippo"))


def _default_output(_nm: nmap.PortScanner):
  try:
    order_dict = xmltodict.parse(_nm.get_nmap_last_output())
    host = _nm.all_hosts()[0]
    json.dump(order_dict, open(f'./result/json/{host}_nm.json', 'w'), indent=2, ensure_ascii=False)
    print(f"[*] Host:{host} Saved.")
  except (KeyError, IndexError):
    print(f"host not alive")
    # sys.exit(0)
  except FileExistsError:
    print(f"[x] Host:{host} JsonFile Exists.")
  except:
    traceback.print_exc()
    sys.exit(0)


if __name__ == '__main__':
  op(finger_scan('113.30.191.68', [2222]))
  # op(finger_scan(
  #   '211.22.90.152', {49152, 8000, 554, 80, 9010}))
