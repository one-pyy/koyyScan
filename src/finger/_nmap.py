import nmap
import sys
from typing import *

from objprint import op
from pitricks.utils import make_parent_top

make_parent_top(2)

from ..model import Ip, Port, Protocal, Service, Finger, Version


def finger_scan(ip: str, ports: List[Port]) -> List[Finger]:
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
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(0)

  try:
    #调用nmap扫描方法
    nm.scan(ip,ports=','.join(map(str, ports)),arguments=' -v -sS -Pn -sV -A')
  except Exception as e:
    print("Scan error:" + str(e))

  ans = []
  # 输出TCP\UDP协议及端口状态
  for proto in nm[ip].all_protocols():
    #获取协议的所有扫描端口
    lport = nm[ip][proto].keys()
    #遍历端口及输出端口与状态
    for port in lport:
      service = Service(nm[ip][proto][port]["product"].lower(),
                        Version(nm[ip][proto][port]["version"]))
      ans.append((port, nm[ip][proto][port]["name"], service))
  return ans

if __name__ == '__main__':
  op(finger_scan('113.30.191.68', [2222]))