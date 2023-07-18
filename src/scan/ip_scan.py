import asyncio as ai
from typing import *
from itertools import groupby

from icmplib import async_ping, async_multiping
from pitricks.utils import make_parent_top

make_parent_top(2)

from ..model import Ip, Port, Protocal, Service, Finger

async def icmp_scan(hosts: Iterable[Ip]):
  icmp_rsp = await async_multiping(hosts, count=2, interval=0.1, timeout=2, concurrent_tasks=500)
  res = {}
  for k, g in groupby(icmp_rsp, lambda x: x.is_alive):
    res.setdefault(k, []).extend(list(g))
  return res

async def ping(hosts: Iterable[Ip]):
  return await icmp_scan(hosts)

if __name__=='__main__':
  from ..utils.arg_parse import ip_range_iterator
  print(ai.get_event_loop().run_until_complete(ping(ip_range_iterator('211.22.90.0/24'))))