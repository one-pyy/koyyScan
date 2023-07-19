from concurrent.futures import ThreadPoolExecutor, as_completed
import logging as lg
import asyncio as ai
import json
from tqdm import tqdm

from objprint import op
from pitricks.utils import init_log

from src import parse_args, gconf, test_ip, test_port_ms, finger_scan
from src.utils.data_format import finger_format


init_log(lg.DEBUG)

if __name__ == '__main__':
  cmd_args = parse_args()
  gconf.update(**cmd_args)
  
  if "run_ip_port" and 0:
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
  
  if "run_finger" and 1:
    ip_port_alive = json.load(open(f"tmp.json", 'r'))
    with ThreadPoolExecutor(max_workers=152) as pool:
      futures = []
      for ip, ports in ip_port_alive.items():
        if ports:
          future = pool.submit(finger_scan, ip, ports)
          future.ip = ip
          futures.append(future)
        else:
          ...#TODO
      
      for future in tqdm(as_completed(futures)):
        json.dump(future.result(), open(f"./result/finger/{future.ip}", 'w'))
  
  # print(list(cmd_args['ip']))
  # result = list()
  # for iport in open('./result_211.22.90.0', 'r'):
  #   ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', iport).group()
  #   port = [re.search(r':\d{1,5}', iport).group()[1:]]
  #   result.append(port_discover(ip, port))
  #   print(port_discover(ip, port))
  # print(result)
