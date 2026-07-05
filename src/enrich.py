#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
보강 모듈 — 신뢰도(confidence), 출처(provenance/citation), 타임라인.

문제 요구사항 중 "출처(citation) 명시 / 신뢰도 스코어링"을 직접 충족한다.
"""

from datetime import date

TODAY = date(2026, 7, 4)


def confidence(vendor_rank: dict, leaks: list, stealers: list) -> dict:
    """
    업체 위험판정의 신뢰도.
      - 활성 인시던트 존재 → 큰 폭 상승 (직접 증거)
      - 유출·스틸러 상호 교차확증(같은 업체에 둘 다) → 상승
      - 출처 다양성 → 상승
    반환: {score(0~1), factors[]}
    """
    factors, s = [], 0.25
    if vendor_rank["counts"]["active_incidents"] > 0:
        s += 0.45
        factors.append("활성 침해 직접 증거(스틸러 HIGH 크리덴셜)")
    if leaks and stealers:
        s += 0.15
        factors.append("유출·스틸러 교차확증")
    sources = {l["source"] for l in leaks}
    if len(sources) >= 2:
        s += 0.10
        factors.append(f"출처 {len(sources)}종 교차")
    s = min(s, 0.97)
    return {"score": round(s, 2), "factors": factors}


def provenance(leaks: list, stealers: list) -> list:
    """출처별 근거 카운트 (citation). 모든 판정은 이 출처들로 소급 가능."""
    prov = {}
    for l in leaks:
        prov.setdefault(l["source"], {"source": l["source"], "type": "leaked_credential", "count": 0})
        prov[l["source"]]["count"] += 1
    for s in stealers:
        key = f"stealer:{s.get('stealer_family','?')}"
        prov.setdefault(key, {"source": key, "type": "stealer_log", "count": 0})
        prov[key]["count"] += 1
    return sorted(prov.values(), key=lambda x: -x["count"])


def timeline(leaks: list, stealers: list, limit=12) -> list:
    """업체 단위 사건 타임라인 (최신순). 대시보드 드릴다운용."""
    ev = []
    for s in stealers:
        cats = sorted({c["category"] for c in s.get("credentials", [])})
        ev.append({"date": s["infection_date"], "kind": "stealer",
                   "label": f"{s['stealer_family']} 감염 ({s['machine_id']})",
                   "detail": "유출 유형: " + ", ".join(cats)})
    for l in leaks:
        ev.append({"date": l["first_seen"], "kind": "leak",
                   "label": f"자격증명 유출 ({l['domain']})",
                   "detail": f"출처: {l['source']}"})
    ev.sort(key=lambda e: e["date"], reverse=True)
    return ev[:limit]
