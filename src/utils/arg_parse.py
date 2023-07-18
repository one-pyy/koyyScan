import argparse

from ..conf import TOP_1000_PORTS
from .misc import get_hosts, get_ports

def parse_args():
  p = argparse.ArgumentParser()

  p.add_argument("-i", "--ip", default='211.22.90.1,211.22.90.152', help="IP range to scan (default '211.22.90.1,211.22.90.152')")
  p.add_argument("-o", "--output", default="out.json", help="Output filename")
  p.add_argument("-p", "--port", default=TOP_1000_PORTS, help="Port to scan (default top 1000)")
  # p.add_argument("-np", "--no-ping", action="store_true", help="Don't check if IP is alive, just scan ports")
  p.add_argument("--proxy", help="SOCKS5 proxy to use")
  p.add_argument("-t", "--threads", default=2000, type=int, help="Number of threads (default 2000)")

  args = vars(p.parse_args())
  args['ip'] = get_hosts(args['ip'])
  args['port'] = get_ports(args['port'])
  return args

