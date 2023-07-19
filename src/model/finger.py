import re
from typing import Tuple, List, NamedTuple, Dict

class Version:
  def __init__(self, ver: str = "") -> None:
    ver_m = re.search(r'[\d.]+', ver)
    ver_list: List[str] = ver_m.group(0).split('.') if ver_m else []
    self.ver: Tuple[int, ...] = tuple(int(x) for x in ver_list)

  def __gt__(self, other: 'Version') -> bool:
    return self.ver > other.ver

  def __lt__(self, other: 'Version') -> bool:
    return self.ver < other.ver
  
  def __eq__(self, other: 'Version') -> bool:
    return self.ver == other.ver
  
  def __contains__(self, other: 'Version') -> bool:
    return self.ver == other.ver[:len(self.ver)]
  
  def __str__(self) -> str:
    return '.'.join(str(x) for x in self.ver) or "N"
  
  def __repr__(self) -> str:
    return self.__str__()
Ver = Version

Ip = str
Port = int
Protocal = str
class Service(NamedTuple):
  name: str
  ver: Version
  
  def __str__(self) -> str:
    return f"{self.name}/{self.ver}"
  
  def __repr__(self) -> str:
    return self.__str__()
  
  @classmethod
  def parse_nmap(cls, input: Dict[str, str]) -> 'Finger':
    ...
Script = dict
  


Finger = List[Tuple[Port, Protocal, List[Service], Script]]

def api_example(ip: Ip, ports: List[Port]) -> List[Finger]: # 蜜罐将放入Service中
  ...

if __name__=='__main__':
  assert(Ver('1.2.3') > Ver('1.2.2'))
  assert(Ver('1.2.3') > Ver('1.2'))
  assert(Ver('1.2.3-alpha') == Ver('1.2.3'))
  assert(Ver() < Ver('1.2'))
  
  assert(Ver('1.2.3') in Ver())
  assert(Ver('1.2.3') in Ver("1.2"))
  assert(Ver('1.2.3') in Ver('1.2.3'))
  assert(Ver('1.2.3') not in Ver('1.2.3.4'))
  assert(Ver('1.2.3') not in Ver('1.3'))
  
  assert(str(Ver())=='N')
  assert(str(Ver('1.2.3'))=='1.2.3')
