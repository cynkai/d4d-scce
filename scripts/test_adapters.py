#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
어댑터 계약 테스트 — MockAdapter/PartnerAdapter가 schema/README.md 계약을 지키는지 검증.

목적: StealthMole 쪽 응답 필드가 바뀌거나, MockAdapter의 합성 데이터 형태가
실수로 바뀌었을 때 파이프라인(matcher/scoring)이 "조용히 빈 결과"를 내는 대신
여기서 바로 잡아낸다.

실행:
  python3 scripts/test_adapters.py            # Mock만 검사(항상 실행 가능, 네트워크 불요)
  python3 scripts/test_adapters.py --partner  # PartnerAdapter 연결까지 포함(네트워크 필요)
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from adapters import MockAdapter, PartnerAdapter, BaseAdapter, get_adapter  # noqa: E402

FAILS = []


def check(label, cond):
    status = "OK" if cond else "FAIL"
    print(f"  [{status}] {label}")
    if not cond:
        FAILS.append(label)


def check_vendor_shape(v):
    return all(k in v for k in ("vendor_id", "name", "tier", "domains", "criticality")) \
        and isinstance(v["domains"], list) and v["domains"]


def check_leak_shape(r):
    return all(k in r for k in ("email", "first_seen", "password_type")) \
        and r["password_type"] in ("plaintext", "hash") \
        and len(str(r["first_seen"]).split("-")) == 3


def check_stealer_shape(s):
    if not all(k in s for k in ("log_id", "stealer_family", "infection_date", "machine_id", "credentials")):
        return False
    if len(str(s["infection_date"]).split("-")) != 3:
        return False
    for c in s["credentials"]:
        if not all(k in c for k in ("url", "category", "username", "password_type")):
            return False
    return True


def test_mock():
    print("\n== MockAdapter ==")
    a = MockAdapter()
    vendors = a.load_vendors()
    leaks = a.load_leaks()
    stealers = a.load_stealers()

    check("load_vendors() 비어있지 않음", bool(vendors))
    check("vendors 필드 계약 준수", vendors and all(check_vendor_shape(v) for v in vendors))
    check("load_leaks() 비어있지 않음", bool(leaks))
    check("leaks 필드 계약 준수", leaks and all(check_leak_shape(r) for r in leaks))
    check("load_stealers() 비어있지 않음", bool(stealers))
    check("stealers 필드 계약 준수", stealers and all(check_stealer_shape(s) for s in stealers))


def test_partner_interface():
    print("\n== PartnerAdapter (인터페이스만, 네트워크 불요) ==")
    check("BaseAdapter 서브클래스", issubclass(PartnerAdapter, BaseAdapter))
    a = PartnerAdapter(vendor_source=MockAdapter())
    check("load_vendors()는 vendor_source로 위임", bool(a.load_vendors()))
    check("check_connection 메서드 존재", callable(getattr(a, "check_connection", None)))
    check("get_adapter('partner')가 PartnerAdapter 반환", isinstance(get_adapter("partner"), PartnerAdapter))


def test_partner_live():
    print("\n== PartnerAdapter (실제 연결 + 실데이터 스키마, 네트워크 필요) ==")
    a = PartnerAdapter(domains=["linkedin.com"], limit=5)
    conn = a.check_connection()
    check("실제 StealthMole 연결/인증 성공", conn.get("ok") is True)
    if not conn.get("ok"):
        print(f"    -> {conn.get('error')} (레이트리밋일 수 있음, 재시도 필요)")
        return
    leaks = a.load_leaks()
    stealers = a.load_stealers()
    check("실제 CL 응답이 leaks 계약 준수 (0건이어도 형태만 확인)",
          all(check_leak_shape(r) for r in leaks))
    check("실제 CDS 응답이 stealers 계약 준수 (0건이어도 형태만 확인)",
          all(check_stealer_shape(s) for s in stealers))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--partner", action="store_true", help="실제 StealthMole 연결까지 테스트")
    args = ap.parse_args()

    test_mock()
    test_partner_interface()
    if args.partner:
        test_partner_live()

    print()
    if FAILS:
        print(f"[FAIL] {len(FAILS)}건 실패: {FAILS}")
        sys.exit(1)
    print("[OK] 전체 통과")


if __name__ == "__main__":
    main()
