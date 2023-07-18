from src import parse_args
from src import finger_scan
from typing import Tuple, List, NamedTuple
import re
import tqdm

if __name__ == '__main__':
  # cmd_args = parse_args()
  # print(list(cmd_args['ip']))
  result = list()
  for iport in open('./result_211.22.90.0', 'r'):
    ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', iport).group()
    port = [re.search(r':\d{1,5}', iport).group()[1:]]
    result.append(finger_scan(ip, port))
    print(finger_scan(ip, port))
  print(result)
