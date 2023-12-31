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
  
  if "run_ip_port" and 1:
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
    ans = {}
    ip_port_alive = json.load(open(f"tmp.json", 'r'))
    with ThreadPoolExecutor(max_workers=10) as pool:
      futures = []
      for ip, ports in ip_port_alive.items():
        if ports and ports.__len__()<100:
          future = pool.submit(finger_scan, ip, ports)
          future.ip = ip
          futures.append(future)
        else:
          ...#TODO
      
      for future in tqdm(as_completed(futures)):
        res = future.result()
        if res is None:
          continue
        json.dump((fingers:=finger_format(future.ip, res[0], res[1], str(res[2]))),
                  open(f'./result/format_json/{future.ip}.json', 'w'), indent=2, ensure_ascii=False)
        for k,v in fingers.items():
          ans[k]=v
    
  json.dump(ans, 
            open(gconf['output'], 'w'))
        # print(future.ip, res)
        # print(future.ip, future.result())
        # print(finger_format(future.ip,future.result()[0],future.result()[1],future.result()[2]))
  
  # print(list(cmd_args['ip']))
  # result = list()
  # for iport in open('./result_211.22.90.0', 'r'):
  #   ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', iport).group()
  #   port = [re.search(r':\d{1,5}', iport).group()[1:]]
  #   result.append(port_discover(ip, port))
  #   print(port_discover(ip, port))
  # print(result)
