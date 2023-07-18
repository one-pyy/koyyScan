from typing import Tuple, List, NamedTuple, Dict

class Device():
    _type: str
    name: str

    def __str__(self) -> str:
        return f"{self._type}/{self.name}"

class Honeypot():
    port: int
    name: str

    def __str__(self) -> str:
        return f"{str(self.int)}/{self.name}"



