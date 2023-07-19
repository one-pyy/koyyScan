# import asyncio as ai
from typing import *
from itertools import groupby

from icmplib import multiping, Host
from pitricks.utils import make_parent_top


make_parent_top(2)

from ..conf import gconf
from ..model import Ip, Port, Protocal, Service, Finger

def test_ip(hosts: Iterable[Ip], repeat = 2) -> Set[Ip]:
  ret = set()
  for _ in range(repeat):
    icmp_rsp = multiping(hosts, count=2, interval=0.01, timeout=10, concurrent_tasks=128)
    res: Dict[bool, List[Host]] = {True: []}
    for k, g in groupby(icmp_rsp, lambda x: x.is_alive):
      res.setdefault(k, []).extend(list(g))
    ret.update(map(lambda x: x.address, res[True]))
  return ret

# async def ping(hosts: Iterable[Ip]):
#   return await icmp_scan(hosts)

if __name__=='__main__':
  from ..utils.arg_parse import get_hosts
  # print(ai.get_event_loop().run_until_complete(test_ip(get_ips('211.22.90.0/24'))))