from typing import Tuple, List, NamedTuple, Dict

class Device(NamedTuple):
    _type: str
    name: str

    def __str__(self) -> str:
        return f"{self._type}/{self.name}"

class Honeypot(NamedTuple):
    port: int
    name: str

    def __str__(self) -> str:
        return f"{str(self.port)}/{self.name}"



