import re
from typing import Tuple, List, NamedTuple
import nmap,sys

class Version:
  def __init__(self, ver: str = "") -> None:
    ver_m = re.search(r'[\d.]+', ver)
    ver_list: List[str] = ver_m.group(0).split('.') if ver_m else []
    self.ver: Tuple[int, ...] = tuple(int(x) for x in ver_list)

  def __gt__(self, other: 'Version') -> bool:
    return self.ver > other.ver

  def __lt__(self, other: 'Version') -> bool:
    return self.ver < other.ver
  
  def __eq__(self, other: 'Version') -> bool:
    return self.ver == other.ver
  
  def __contains__(self, other: 'Version') -> bool:
    return self.ver == other.ver[:len(self.ver)]
  
  def __str__(self) -> str:
    return '.'.join(str(x) for x in self.ver) or "N"
Ver = Version


Port = int
Protocal = str
class Service(NamedTuple):
  name: str
  ver: Version
  
  def __str__(self) -> str:
    return f"{self.name}/{self.ver}"

Finger = List[Tuple[Port, Protocal, List[Service]]]

def api_example(ip: str, ports: List[Port]) -> List[Finger]: # 蜜罐将放入Service中
  ...

def port_discover(ip: str, ports: List[Port]) -> List[Finger]:
  try:
      #创建端口扫描对象
      nm = nmap.PortScanner()
  except nmap.PortScannerError:
      print('Nmap not found', sys.exc_info()[0])
      sys.exit(0)
  except:
      print("Unexpected error:", sys.exc_info()[0])
      sys.exit(0)

  try:
      #调用nmap扫描方法
      nm.scan(ip,ports=','.join(map(str,ports)),arguments=' -v -sS -Pn -sV -O')
  except Exception as e:
      print("Scan error:"+str(e))
  
  ans = []
  # 输出TCP协议及端口状态
  for proto in nm[ip].all_protocols():
          #获取协议的所有扫描端口        
          lport = nm[ip][proto].keys()
          #遍历端口及输出端口与状态
          for port in lport:
              service = Service(nm[ip][proto][port]["name"],Version(nm[ip][proto][port]["version"]))
              ans.append(tuple([port,proto,service]))
  return ans

if __name__=='__main__':
  assert(Ver('1.2.3') > Ver('1.2.2'))
  assert(Ver('1.2.3') > Ver('1.2'))
  assert(Ver('1.2.3-alpha') == Ver('1.2.3'))
  assert(Ver() < Ver('1.2'))
  
  assert(Ver('1.2.3') in Ver())
  assert(Ver('1.2.3') in Ver("1.2"))
  assert(Ver('1.2.3') in Ver('1.2.3'))
  assert(Ver('1.2.3') not in Ver('1.2.3.4'))
  assert(Ver('1.2.3') not in Ver('1.3'))
  
  assert(str(Ver())=='N')
  assert(str(Ver('1.2.3'))=='1.2.3')
