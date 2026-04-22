from abc import ABC, abstractmethod
from typing import List, Generator, Tuple
from core.models import AttackSurface, Payload

class BaseModule(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def get_payloads(self) -> List[Payload]:
        """config/payloads/ 에서 페이로드를 로드하거나 리스트를 반환"""
        pass

    @abstractmethod
    def analyze(self, response, payload: Payload, elapsed_time: float) -> bool:
        """취약점 여부 분석 (추상 메서드)"""
        pass