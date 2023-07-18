import asyncio as ai
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, sr
from typing import Iterable, List, Dict, Set
import masscan
import json

# from obj_walker import obj_walker as ow, obj_searcher

from pitricks.utils import make_parent_top
make_parent_top(2)

from ..model import Ip, Port
from ..conf import gconf
from ..utils import get_top_ports

def test_port(ip: Ip, ports: List[Port]):
  ans = sr(IP(dst=ip)/TCP(dport=list(ports), flags='S'), 
            timeout=60, verbose=0, threaded=True, prebuild=True)
  
  op_ports = [
    rsp[0].payload.dport
    for rsp in ans[0].res]
  return op_ports

TOP_250 = get_top_ports(250)
def test_port_ms(hosts: List[Ip], alive_ip: List[Ip], 
                 ports: List[Port], lots_ports: List[Port], 
                 repeat = 2) -> Dict[Ip, Set[Port]]:
  ret = {ip: set() for ip in alive_ip}
  def t(hosts: Iterable[Ip], ports: List[Port]):
    mas = masscan.PortScanner()
    mas.scan(",".join(hosts), ports=",".join(map(str, ports)), arguments=f'--max-rate {gconf["threads"]}')
    scan_ans = json.loads(mas.scan_result)['scan']
    for k,v in scan_ans.items():
      ret.setdefault(k, set()).update(info['port'] for info in v)
  for _ in range(repeat):
    t(hosts, TOP_250)
  for _ in range(repeat):
    t(hosts, ports)
  for _ in range(repeat):
    t(ret.keys(), lots_ports)
  return ret

if __name__ == '__main__':
  print(test_port('211.22.90.152', list(range(25000, 35000))))