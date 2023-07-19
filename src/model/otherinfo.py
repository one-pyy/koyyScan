from typing import Tuple, List, NamedTuple, Dict

class Device(NamedTuple):
    type_: str
    name: str

    def __str__(self) -> str:
        return f"{self.type_}/{self.name}"
    
    def __repr__(self) -> str:
        return self.__str__()

class Honeypot(NamedTuple):
    port: int
    name: str

    def __str__(self) -> str:
        return f"{str(self.port)}/{self.name}"
    def __repr__(self) -> str:
        return self.__str__()



