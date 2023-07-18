import ipaddress

from ..conf import TOP_30000_PORTS

def get_hosts(cidrs):
  hosts = []
  for cidr in cidrs.split(','):
    network = ipaddress.ip_network(cidr)
    hosts += [str(ip) for ip in network.hosts()]
  return hosts

def get_ports(port_range):
  ports = []
  for p in port_range.split(','):
    if '-' in p:
      start, end = p.split('-')
      for port in range(int(start), int(end)+1):
        ports.append(port)
    else:
      ports.append(int(p))
  return ports

TOP_30000_PORTS = get_ports(TOP_30000_PORTS)
def get_top_ports(top: int):
  assert(0<top<=30000)
  return TOP_30000_PORTS[:top]