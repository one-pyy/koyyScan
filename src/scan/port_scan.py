import asyncio as ai
from typing import Iterable, List, Dict, Set
import json
import logging as lg
import os
from uuid import uuid4
import pexpect
import re

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, sr
import masscan

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

ip_port_pattern = r"Discovered open port (\d+)/[^ ]* on ([.\d]+)"
ip_port_reg = re.compile(ip_port_pattern)
def run_mas_shell(shell: str):
  ret = []
  proc = pexpect.spawn(shell)
  while True:
    proc.expect(["waiting -2", pexpect.EOF, ip_port_pattern])
    if proc.after not in (b"waiting -2", pexpect.EOF):
      port, ip = re.findall(ip_port_reg, proc.after.decode('utf-8'))[0]
      ret.append((ip, port))
    else:
      break
  proc.close()
  return ret

def run_mas(hosts: Iterable[Ip], ports: List[Port]):
  return run_mas_shell(
    f"masscan -p {','.join(map(str, ports))} {','.join(hosts)} --rate {gconf['threads']}")

TOP_250 = get_top_ports(250)
def test_port_ms(hosts: List[Ip], alive_ip: List[Ip], 
                 ports: List[Port], lots_ports: List[Port], 
                 repeat = 2) -> Dict[Ip, List[Port]]:
  ret = {ip: set() for ip in alive_ip}
  
  def t(hosts: Iterable[Ip], ports: List[Port]):
    scan_ans = run_mas(hosts, ports)
    for e in scan_ans:
      ret.setdefault(e[0], set()).add(e[1])
  
  for _ in range(repeat):
    t(hosts, TOP_250)
  lg.info(f"TOP 250 ports scan done, {len(ret)} hosts alive")
  lg.debug(f"result: {ret}")
  
  for _ in range(repeat):
    t(hosts, ports)
  lg.info(f"TOP {ports.__len__()} ports scan done, {len(ret)} hosts alive")
  lg.debug(f"result: {ret}")

  # for _ in range(repeat):
  t(ret.keys(), lots_ports)
  lg.info(f"TOP {lots_ports.__len__()} ports scan done")
  lg.debug(f"result: {ret}")
  
  async def t2(ip: Ip, port: Port):
    for _ in range(3):
      if await test_connect(ip, port):
        return
    lg.debug(f"port {port} of {ip} is not alive")
    ret[ip].discard(port)
  
  ai.set_event_loop(ai.new_event_loop())
  ai.get_event_loop().run_until_complete(
    ai.gather(*[t2(ip, port) for ip in ret.keys() for port in ret[ip]]))
  lg.info("port connect test done")
  
  for k,v in ret.items():
    ret[k] = list(v)
  
  return ret

async def test_connect(ip: Ip, port: Port):
  try:
    reader, writer = await ai.open_connection(ip, port)
    writer.close()
    await writer.wait_closed()
    return True
  except OSError as e:
    return False

if __name__ == '__main__':
  print(ai.get_event_loop().run_until_complete(test_connect("211.22.90.1", 111)))
  # print(test_port('211.22.90.152', list(range(25000, 35000))))