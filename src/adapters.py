#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
데이터 소스 어댑터 — 파이프라인을 데이터 출처로부터 분리한다.

MockAdapter    : 합성/공개 데이터. 오프라인 확정 동작. (메인)
PartnerAdapter : StealthMole 등 파트너 API. 현장에서 접근 확보되면 여기만 구현. (옵션)

파이프라인은 어댑터 인터페이스(load_*)만 호출하므로,
현장에서 무엇을 쓰든 파이프라인 코드는 안 바뀐다.
"""

import json
import os


class BaseAdapter:
    def load_vendors(self) -> list: raise NotImplementedError
    def load_leaks(self) -> list: raise NotImplementedError
    def load_stealers(self) -> list: raise NotImplementedError


class MockAdapter(BaseAdapter):
    """합성 데이터 로더. data/synthetic/*.json 을 읽는다."""

    def __init__(self, base_dir=None):
        self.dir = base_dir or os.path.join(
            os.path.dirname(__file__), "..", "data", "synthetic")

    def _load(self, name):
        with open(os.path.join(self.dir, name), encoding="utf-8") as f:
            return json.load(f)

    def load_vendors(self):  return self._load("vendors.json")
    def load_leaks(self):    return self._load("leaked_credentials.json")
    def load_stealers(self): return self._load("stealer_logs.json")


class PartnerAdapter(BaseAdapter):
    """
    파트너(StealthMole) API 어댑터. 인증/연결(src/stealthmole_client.py)과
    CL(유출 자격증명)/CDS(감염기기 로그) 정규화 매핑까지 실제로 붙어 있다.

    주의(실사용 전 확인할 것):
    - CDS 응답엔 stealer_family(악성코드 계열)가 없다 — StealthMole이 안 준다.
      "Unknown"으로 표기하고, credentials[].category 는 host 문자열 키워드로
      추정(best-effort)한다(stealthmole_client.classify_category). 실제 서비스명이
      synthetic 데이터의 명명 관례(vpn./sso./admin.../git....)를 따르지 않으면
      카테고리가 틀릴 수 있다 — 즉 활성침해 판정 정확도가 합성 데이터보다 낮다.
    - vendors 는 우리가 정의(협력사 목록)하므로 Mock 것을 그대로 씀.
    - self.domains 를 안 주면 vendors.json의 도메인을 자동으로 순회한다.
    """

    def __init__(self, vendor_source=None, domains=None, limit=50):
        self.vendor_source = vendor_source or MockAdapter()
        self.domains = domains
        self.limit = limit

    def load_vendors(self):
        return self.vendor_source.load_vendors()

    def _domains(self):
        if self.domains:
            return self.domains
        out = []
        for v in self.load_vendors():
            out.extend(v.get("domains", []))
        return out

    def check_connection(self):
        """실제 StealthMole API 연결/인증 증명 (PII 없음, /user/quotas 헬스체크)."""
        import stealthmole_client as sm
        return sm.check_quota()

    def load_leaks(self):
        import stealthmole_client as sm
        out, rid = [], 0
        for domain in self._domains():
            data, error = sm.search_domain("cl", domain, limit=self.limit)
            if error:
                continue
            for item in (data or {}).get("data", []):
                rid += 1
                out.append({
                    "record_id": f"CL-{rid:05d}",
                    "email": item.get("email", ""),
                    "domain": item.get("domain", domain),
                    "password_type": "plaintext",  # CL이 해시 여부를 안 줌 — 보수적 기본값
                    "source": f"stealthmole:cl:{item.get('leaked_from', 'unknown')}",
                    "first_seen": sm.to_iso_date(item.get("leaked_date")),
                })
        return out

    def load_stealers(self):
        import stealthmole_client as sm
        out = {}  # machine_id -> log dict (CDS는 자격증명 단위 flat 목록이라 단말 기준으로 재조립)
        for domain in self._domains():
            data, error = sm.search_domain("cds", domain, limit=self.limit)
            if error:
                continue
            for item in (data or {}).get("data", []):
                machine = item.get("computername") or item.get("id", "UNKNOWN")
                infection_date = sm.to_iso_date(item.get("leakeddate") or item.get("regdate"))
                log = out.setdefault(machine, {
                    "log_id": f"CDS-{machine}",
                    "stealer_family": "Unknown",  # StealthMole CDS는 악성코드 계열을 안 줌
                    "infection_date": infection_date,
                    "machine_id": machine,
                    "country": "unknown",
                    "credentials": [],
                })
                host = item.get("host", domain)
                log["credentials"].append({
                    "url": f"https://{host}/",
                    "category": sm.classify_category(host),  # best-effort 추정, 상단 클래스 docstring 참고
                    "username": item.get("username") or item.get("user", ""),
                    "password_type": "plaintext",
                })
        return list(out.values())


def get_adapter(source="mock", **kw) -> BaseAdapter:
    if source == "mock":
        return MockAdapter(**kw)
    if source == "partner":
        return PartnerAdapter(**kw)
    raise ValueError(f"unknown source: {source}")
