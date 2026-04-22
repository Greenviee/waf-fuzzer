"""
로깅 유틸리티
프로젝트 전체에서 사용하는 로거 설정

담당: 공통 모듈
"""

import logging
import sys
from datetime import datetime


# 로거 캐시 (중복 생성 방지)
_loggers = {}


def get_logger(name, level=logging.INFO, log_file=None):
    """
    로거 인스턴스 생성

    Args:
        name: 로거 이름 (보통 __name__ 사용)
        level: 로깅 레벨 (DEBUG, INFO, WARNING, ERROR)
        log_file: 로그 파일 경로 (선택)

    Returns:
        설정된 로거 인스턴스

    사용 예시:
        from utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("메시지")
    """
    # 이미 생성된 로거면 반환
    if name in _loggers:
        return _loggers[name]

    # 로거 생성
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 이미 핸들러가 있으면 스킵 (중복 방지)
    if logger.handlers:
        _loggers[name] = logger
        return logger

    # 포맷 설정
    formatter = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 콘솔 핸들러
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 파일 핸들러 (선택)
    if log_file is not None:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning("로그 파일 생성 실패: %s", e)

    # 캐시에 저장
    _loggers[name] = logger

    return logger


def set_level(level):
    """
    모든 로거의 레벨 변경

    Args:
        level: logging.DEBUG, logging.INFO 등
    """
    for logger in _loggers.values():
        logger.setLevel(level)
        for handler in logger.handlers:
            handler.setLevel(level)


def enable_debug():
    """디버그 모드 활성화"""
    set_level(logging.DEBUG)


def disable_debug():
    """디버그 모드 비활성화 (INFO로 복귀)"""
    set_level(logging.INFO)


# 간단한 전역 로거 (선택적 사용)
default_logger = get_logger('vuln_scanner')