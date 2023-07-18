from src import parse_args
from src import port_discover
from typing import Tuple, List, NamedTuple
import re

if __name__=='__main__':
  # cmd_args = parse_args()
  # print(list(cmd_args['ip']))
  result = []
  for iport in open('./result_211.22.90.0','r'):
    ip = re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',iport).group()
    port = list(re.search(':\d{1,5}',iport).group()[1:])
    result.append(port_discover(ip,port))
  print(result)