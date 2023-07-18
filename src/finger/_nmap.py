import nmap
import sys
from typing import *

from objprint import op
from pitricks.utils import make_parent_top

make_parent_top(2)

from ..model import Ip, Port, Protocal, Service, Finger, Version

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
    nm.scan(ip,
            ports=','.join(map(str, ports)),
            arguments=' -v -sS -Pn -sV -O')
  except Exception as e:
    print("Scan error:" + str(e))

  ans = []
  # 输出TCP协议及端口状态
  for proto in nm[ip].all_protocols():
    #获取协议的所有扫描端口
    lport = nm[ip][proto].keys()
    #遍历端口及输出端口与状态
    for port in lport:
      op(nm[ip][proto][port])
      service = Service(nm[ip][proto][port]["name"],
                        Version(nm[ip][proto][port]["version"]))
      ans.append((port, proto, service))
  return ans

if __name__ == '__main__':
  op(port_discover('113.30.191.68', [2222]))