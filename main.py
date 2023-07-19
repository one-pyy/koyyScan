from concurrent.futures import ThreadPoolExecutor, as_completed
import logging as lg
import asyncio as ai
import json

from objprint import op
from pitricks.utils import init_log

from src import parse_args, gconf, test_ip, test_port_ms, finger_scan
from src.utils.data_format import finger_format


init_log(lg.DEBUG)

if __name__ == '__main__':
  cmd_args = parse_args()
  gconf.update(**cmd_args)
  
  ip_alive = list(test_ip(gconf['ip']))
  ip_alive.sort()
  lg.info(f"IP alive: {ip_alive}")
  
  ip_port_alive = test_port_ms(gconf['ip'], ip_alive, gconf['port'], gconf['aport'])
  for ip in ip_alive:
    if ip not in ip_port_alive:
      ip_port_alive[ip] = set()
  lg.info(f"IP-port alive: {ip_port_alive}")
  
  json.dump(ip_port_alive, open(f"tmp.json", 'w'),
            indent=2, ensure_ascii=False)
  
  def run_finger():
    with ThreadPoolExecutor(max_workers=80) as pool:
      futures = []
      for ip, ports in ip_port_alive.items():
        future = pool.submit(finger_scan, ip, ports)
        future.ip = ip
        futures.append(future)
      
      for future in as_completed(futures):
        print(future.ip, future.result())
  # run_finger()
  
  # print(list(cmd_args['ip']))
  # result = list()
  # for iport in open('./result_211.22.90.0', 'r'):
  #   ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', iport).group()
  #   port = [re.search(r':\d{1,5}', iport).group()[1:]]
  #   result.append(port_discover(ip, port))
  #   print(port_discover(ip, port))
  # print(result)
