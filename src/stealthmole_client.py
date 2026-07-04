#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StealthMole API 클라이언트 — Foundry 없이 standalone으로 붙이는 버전.

Foundry 세션 자료(helpers.py)의 인증 패턴을 그대로 이식:
  JWT(HS256) payload = {access_key, nonce(uuid4), iat} → secret_key로 서명
  → Authorization: Bearer <token>

키는 오직 환경변수(.env)에서만 읽는다. 코드에 하드코딩 금지, 로그에 값 출력 금지.
"""

import datetime
import logging
import os
import time
import uuid

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://hackathon.stealthmole.com"  # 해커톤 전용 엔드포인트(비밀 아님)
MAX_RETRIES = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

_response_cache = {}  # (service_code, domain, limit) -> (data, error) — 같은 실행 내 중복 호출 방지


def _load_env():
    """.env 를 있으면 로드. python-dotenv 없으면 조용히 건너뜀(이미 export된 환경변수로도 동작)."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def get_credentials():
    """
    환경변수에서만 키를 읽는다. 반환값을 로그/print/예외 메시지에 절대 포함하지 말 것.
    """
    _load_env()
    access_key = os.environ.get("STEALTHMOLE_ACCESS_KEY")
    secret_key = os.environ.get("STEALTHMOLE_SECRET_KEY")
    base_url = os.environ.get("STEALTHMOLE_BASE_URL", DEFAULT_BASE_URL)
    if not access_key or not secret_key:
        raise RuntimeError(
            "STEALTHMOLE_ACCESS_KEY / STEALTHMOLE_SECRET_KEY 가 환경변수(.env)에 없습니다.")
    return access_key, secret_key, base_url


def generate_jwt(access_key: str, secret_key: str) -> str:
    """StealthMole JWT 토큰 생성 (매 요청마다 새로 생성)."""
    import jwt  # PyJWT
    payload = {
        "access_key": access_key,
        "nonce": str(uuid.uuid4()),
        "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


def get_auth_headers(access_key: str, secret_key: str) -> dict:
    token = generate_jwt(access_key, secret_key)
    return {"Authorization": "Bearer " + token}


def safe_api_call(url: str, make_headers, timeout: int = 30, max_retries: int = MAX_RETRIES):
    """
    API 호출 + 에러 핸들링 + 로깅(응답 본문은 길이만 로깅, 값은 로깅하지 않음).
    429/5xx 는 지수 백오프로 재시도한다. Retry-After 헤더가 있으면 그걸 우선한다.

    make_headers: 인자 없는 콜러블 — 시도마다 새로 호출해 JWT를 재생성한다.
    (JWT는 iat/nonce가 실려 있어 재시도 대기 후 오래된 토큰을 재사용하면
    서버가 401로 거부할 수 있다 — 매 시도 새 토큰 발급으로 해결.)
    """
    import requests
    attempt = 0
    while True:
        headers = make_headers()
        logger.info("Calling API: %s (attempt %s)", url, attempt + 1)
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
        except Exception as e:
            error_msg = f"Exception: {type(e).__name__}"
            logger.error(error_msg)
            return None, error_msg

        logger.info("Status: %s, Size: %s bytes", response.status_code, len(response.content))
        if response.status_code in (200, 202):
            return response.json(), None

        if response.status_code in RETRYABLE_STATUS and attempt < max_retries:
            retry_after = response.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else (2 ** attempt) * 1.0
            except ValueError:
                wait = (2 ** attempt) * 1.0
            wait = min(wait, 15.0)
            logger.warning("HTTP %s — retrying in %.1fs (attempt %s/%s)",
                            response.status_code, wait, attempt + 1, max_retries)
            time.sleep(wait)
            attempt += 1
            continue

        error_msg = f"HTTP {response.status_code}"
        logger.error(error_msg)
        return None, error_msg


def check_quota():
    """
    연결/인증 증명용 헬스체크. PII 없음 — 서비스별 쿼터(allowed/used)만 반환.
    데모/CLI에서 "실제 StealthMole API에 진짜로 붙는다"를 증명하는 용도.
    """
    access_key, secret_key, base_url = get_credentials()
    data, error = safe_api_call(base_url + "/user/quotas",
                                 lambda: get_auth_headers(access_key, secret_key))
    if error:
        return {"ok": False, "error": error}
    rows = [{"service": s, "allowed": v.get("allowed"), "used": v.get("used")}
            for s, v in (data or {}).items()]
    return {"ok": True, "quotas": rows}


HIGH_CATEGORY_KEYWORDS = {
    "vpn": ("vpn",),
    "sso": ("sso", "adfs", "okta"),
    "admin_panel": ("admin", "erp"),
    "cloud_console": ("console", "cloud"),
    "code_repo": ("git", "repo"),
}
LOW_CATEGORY_KEYWORDS = {
    "webmail": ("mail", "owa"),
    "saas": ("slack", "saas"),
}


def classify_category(host: str) -> str:
    """
    호스트명 키워드로 category 추정(best-effort). 실 API는 category를 안 주므로
    schema/README.md 의 URL 명명 관례(vpn./sso./admin./console./git.)를 기준으로 유추한다.
    실제 서비스명이 이 관례를 따르지 않으면 틀릴 수 있음 — "generic"으로 보수적으로 폴백.
    """
    h = (host or "").lower()
    for cat, kws in HIGH_CATEGORY_KEYWORDS.items():
        if any(kw in h for kw in kws):
            return cat
    for cat, kws in LOW_CATEGORY_KEYWORDS.items():
        if any(kw in h for kw in kws):
            return cat
    return "generic"


def to_iso_date(raw, default_iso=None):
    """
    StealthMole 날짜 필드 정규화. 관측된 형태: 유닉스 타임스탬프(int),
    'YYYY-MM-DD', 'YYYY-MM' 등. scoring.py의 freshness()는 반드시
    'YYYY-MM-DD' 3파트를 기대하므로 여기서 통일한다.
    """
    if raw is None:
        return default_iso
    if isinstance(raw, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(raw, tz=datetime.timezone.utc).date().isoformat()
        except (ValueError, OSError):
            return default_iso
    s = str(raw)
    parts = s.split("-")
    if len(parts) == 3:
        return s
    if len(parts) == 2:
        return s + "-01"
    return default_iso


_last_call_at = [0.0]
MIN_CALL_INTERVAL = 0.35  # 초당 요청 수를 조절해 애초에 429를 덜 맞도록


def _pace():
    elapsed = time.monotonic() - _last_call_at[0]
    if elapsed < MIN_CALL_INTERVAL:
        time.sleep(MIN_CALL_INTERVAL - elapsed)
    _last_call_at[0] = time.monotonic()


def search_domain(service_code: str, domain: str, limit: int = 3, use_cache: bool = True):
    """
    서비스별 도메인 검색 (CL=Credential Lookout, CB=Credential Bot 등).
    응답 필드 스키마는 공개 문서로 확인되지 않아 원본 JSON을 그대로 반환한다.
    실데이터 파이프라인에 정식으로 연결하려면 실제 응답을 보고 정규화 매핑을 추가해야 한다.

    같은 (service, domain, limit) 조합은 프로세스 내에서 캐시해 중복 호출·쿼터 낭비를 줄인다.
    호출 전 최소 간격(MIN_CALL_INTERVAL)을 둬 연속 다건 조회 시 레이트리밋에 덜 걸리게 한다.
    """
    ENDPOINTS = {
        "cl": "/cl/search?query=domain:{domain}&limit={limit}",
        "cb": "/cb/search?query=domain:{domain}&limit={limit}",
        "cds": "/cds/search?query=domain:{domain}&limit={limit}",
    }
    if service_code not in ENDPOINTS:
        raise ValueError(f"unsupported service_code: {service_code}")

    cache_key = (service_code, domain, limit)
    if use_cache and cache_key in _response_cache:
        return _response_cache[cache_key]

    access_key, secret_key, base_url = get_credentials()
    url = (base_url + ENDPOINTS[service_code]).format(domain=domain, limit=limit)

    _pace()
    result = safe_api_call(url, lambda: get_auth_headers(access_key, secret_key))
    if use_cache:
        _response_cache[cache_key] = result
    return result
