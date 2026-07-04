#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StealthMole 실제 연결 확인 (로컬 전용).

  python3 scripts/check_stealthmole.py

.env 의 STEALTHMOLE_ACCESS_KEY / STEALTHMOLE_SECRET_KEY 로 JWT 인증 후
/user/quotas 를 호출한다. PII 없는 헬스체크이므로 결과를 그대로 터미널에
출력해도 안전하다 — 이 출력을 캡처해서 공유해도 키/개인정보는 안 담긴다.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import stealthmole_client as sm  # noqa: E402


def main():
    print("StealthMole 연결 확인 중...")
    result = sm.check_quota()
    if not result["ok"]:
        print(f"[실패] {result['error']}")
        print("확인할 것: .env의 STEALTHMOLE_ACCESS_KEY/STEALTHMOLE_SECRET_KEY, "
              "네트워크(hackathon.stealthmole.com 접근 가능 여부)")
        sys.exit(1)
    print("[성공] 인증 통과. 서비스별 쿼터:")
    for row in result["quotas"]:
        print(f"  - {row['service']:6s} used={row['used']} / allowed={row['allowed']}")


if __name__ == "__main__":
    main()
