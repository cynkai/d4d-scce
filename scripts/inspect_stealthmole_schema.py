#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StealthMole 응답 스키마(필드 이름만) 확인용 — 로컬 전용.

  python3 scripts/inspect_stealthmole_schema.py <domain> [service]
  예:
    python3 scripts/inspect_stealthmole_schema.py linkedin.com cl
    python3 scripts/inspect_stealthmole_schema.py linkedin.com cb

실제 leaked 값(이메일/비밀번호/URL 등)은 절대 출력하지 않는다 — 각 leaf 값을
타입과 길이로만 치환해서 보여준다. 이 출력 결과는 PII가 없으므로 그대로
복사해서 공유해도 안전하다.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import stealthmole_client as sm  # noqa: E402


def redact(obj, depth=0):
    """dict/list 구조(키 이름)는 유지하고, leaf 값은 타입+길이로만 치환."""
    if depth > 6:
        return "…(too deep)"
    if isinstance(obj, dict):
        return {k: redact(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        if not obj:
            return []
        # 리스트는 첫 항목 구조만 보여주고 나머지는 개수만
        return [redact(obj[0], depth + 1), f"...(+{len(obj) - 1} more)" if len(obj) > 1 else None]
    if obj is None:
        return None
    if isinstance(obj, bool):
        return f"<bool>"
    if isinstance(obj, (int, float)):
        return f"<{type(obj).__name__}>"
    s = str(obj)
    return f"<str len={len(s)}>"


def main():
    if len(sys.argv) < 2:
        print("사용법: python3 scripts/inspect_stealthmole_schema.py <domain> [cl|cb|cds]")
        sys.exit(1)
    domain = sys.argv[1]
    service = sys.argv[2] if len(sys.argv) > 2 else "cl"

    print(f"조회 중: service={service} domain={domain} (limit=1)")
    data, error = sm.search_domain(service, domain, limit=1)
    if error:
        print(f"[실패] {error}")
        sys.exit(1)

    import json
    print("--- 필드 스키마 (값은 전부 타입/길이로 치환됨, PII 없음) ---")
    print(json.dumps(redact(data), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
