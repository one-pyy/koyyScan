from src import parse_args
from src import port_discover
from typing import Tuple, List, NamedTuple
import re
import tqdm

if __name__=='__main__':
  # cmd_args = parse_args()
  # print(list(cmd_args['ip']))
  result = list()
  pbar = tqdm(total=19)
  for iport in tqdm(open('./result_211.22.90.0','r')):
    ip = re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',iport).group()
    port = list(re.search(':\d{1,5}',iport).group()[1:])
    result.append(port_discover(ip,port))
    pbar.update(1)
  pbar.close()
  print(result)