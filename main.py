from src import parse_args, gconf, test_ip, test_port_ms, finger_scan
import re
import tqdm

if __name__ == '__main__':
  cmd_args = parse_args()
  gconf.update(**cmd_args)
  
  ip_alive = test_ip(gconf['ip'])
  print("IP alive: ", ip_alive)
  ip_port_alive = test_port_ms(gconf['ip'], gconf['port'])
  print("IP-port alive:", ip_port_alive)
  # print(list(cmd_args['ip']))
  # result = list()
  # for iport in open('./result_211.22.90.0', 'r'):
  #   ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', iport).group()
  #   port = [re.search(r':\d{1,5}', iport).group()[1:]]
  #   result.append(port_discover(ip, port))
  #   print(port_discover(ip, port))
  # print(result)
