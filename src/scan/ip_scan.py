# import asyncio as ai
from typing import *
from itertools import groupby

from icmplib import async_ping, async_multiping, multiping, Host
from pitricks.utils import make_parent_top


make_parent_top(2)

from ..conf import gconf
from ..model import Ip, Port, Protocal, Service, Finger

def test_ip(hosts: Iterable[Ip], repeat = 3) -> Set[Ip]:
  ret = set()
  for _ in range(repeat):
    icmp_rsp = multiping(hosts, count=2, interval=0.1, timeout=2, concurrent_tasks=gconf['threads'])
    res: Dict[bool, List[Host]] = {}
    for k, g in groupby(icmp_rsp, lambda x: x.is_alive):
      res.setdefault(k, []).extend(list(g))
    ret.update(map(lambda x: x.address, res[True]))
  return ret

# async def ping(hosts: Iterable[Ip]):
#   return await icmp_scan(hosts)

if __name__=='__main__':
  from ..utils.arg_parse import get_hosts
  # print(ai.get_event_loop().run_until_complete(test_ip(get_ips('211.22.90.0/24'))))