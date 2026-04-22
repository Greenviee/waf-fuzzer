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

    def generate_test_cases(self, surface: AttackSurface) -> Generator[Tuple[str, Payload, AttackSurface], None, None]:
        """
        AttackSurface의 모든 파라미터에 대해 페이로드를 하나씩 주입해봄
        yield (주입된_파라미터_명, 사용된_페이로드, 수정된_AttackSurface)
        """
        payloads = self.get_payloads()
        for payload in payloads:
            for key in surface.parameters.keys():
                # 파라미터 변조
                modified_params = surface.parameters.copy()
                modified_params[key] = payload.value
                
                # 변조된 새로운 AttackSurface 생성
                new_surface = AttackSurface(
                    url=surface.url,
                    method=surface.method,
                    param_location=surface.param_location,
                    parameters=modified_params,
                    headers=surface.headers.copy(),
                    cookies=surface.cookies.copy()
                )
                yield key, payload, new_surface