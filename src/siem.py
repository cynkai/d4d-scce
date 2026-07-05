#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM 엔진 — 원시 신호를 타임스탬프·룰 태그가 붙은 보안 이벤트 스트림으로 정규화.

collect(원시 로그) → detect(룰 발화) 층. 이 스트림에서 탐지가 발화하고,
그 결과가 인시던트 큐·조사 화면·보고서/탐지룰로 흘러간다.
"""

import random
from datetime import date, timedelta

TODAY = date(2026, 7, 4)
HIGH = {"vpn", "sso", "admin_panel", "cloud_console", "code_repo"}
CAT_KO = {"vpn": "VPN", "sso": "SSO", "admin_panel": "ERP/관리자", "cloud_console": "클라우드콘솔",
          "code_repo": "코드저장소", "webmail": "웹메일", "saas": "SaaS", "generic": "포털"}


def _ts(rng, iso):
    """day-level 날짜에 합성 시:분:초를 붙여 datetime 문자열."""
    return f"{iso} {rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"


def build_siem(vendors, leaks, stealers, campaigns, seed=42):
    rng = random.Random(seed)
    vname = {v["vendor_id"]: v["name"] for v in vendors}
    camp_machines = {m for c in campaigns for m in c.get("machines", [])}
    camp_c2 = {c["c2_host"]: c for c in campaigns if c.get("c2_host")}
    events = []

    def ev(ts, sev, source, vendor_id, rule, msg, mitre=None):
        events.append({
            "ts": ts, "severity": sev, "source": source,
            "vendor": vname.get(vendor_id), "vendor_id": vendor_id,
            "rule": rule, "message": msg, "mitre": mitre or [],
        })

    # 스틸러 감염 이벤트 (전부)
    for s in stealers:
        vid = s.get("vendor_id")
        cats = sorted({c["category"] for c in s.get("credentials", []) if c["category"] in HIGH})
        active = bool(vid and cats)
        ts = _ts(rng, s["infection_date"])
        if active:
            ev(ts, "critical", "stealer", vid, "ACTIVE-COMPROMISE",
               f"{s['stealer_family']} 감염 · {s['machine_id']} · 내부망 유출 "
               f"({', '.join(CAT_KO.get(c, c) for c in cats)})", ["T1555", "T1078"])
        elif vid:
            ev(ts, "high", "stealer", vid, "STEALER-INFECTION",
               f"{s['stealer_family']} 감염 탐지 · {s['machine_id']}", ["T1555"])
        # C2 비콘
        if s.get("c2_host"):
            sev = "critical" if s["c2_host"] in camp_c2 else "medium"
            ev(_ts(rng, s["infection_date"]), sev, "c2", vid,
               "C2-BEACON" if s["c2_host"] not in camp_c2 else "CAMPAIGN-C2",
               f"C2 비콘 관측 · {s['c2_host']}" + (f" · {s['stealer_family']}" if s.get("stealer_family") else ""))

    # 유출 자격증명 이벤트 (협력사 대상 표본)
    corp_leaks = [l for l in leaks if l.get("vendor_id")]
    for l in rng.sample(corp_leaks, min(45, len(corp_leaks))):
        sev = "high" if l.get("password_type") == "plaintext" else "medium"
        ev(_ts(rng, l["first_seen"]), sev, "cred_leak", l["vendor_id"], "CRED-LEAK",
           f"유출 자격증명 관측 · {l['domain']} · 출처 {l['source']}")

    # 캠페인 상관 탐지 (룰 발화)
    for c in campaigns:
        ev(_ts(rng, c["last_seen"]), "critical", "correlation", None, "CAMPAIGN-CORRELATION",
           f"조율 캠페인 탐지 · {c['campaign_id']} · {c['affected_count']}개 협력사 · "
           f"동일 C2({c['c2_host']})/스틸러({c['stealer_family']})", ["T1195.002"])
        # 조기경보
        ev(f"{c['last_seen']} 09:00:00", "critical", "early_warning", None, "EARLY-WARNING",
           f"조기경보 발령 · {c['campaign_id']} 공급망 표적 정황")

    # 시간순 정렬(오래된→최신)
    events.sort(key=lambda e: e["ts"])
    for i, e in enumerate(events, 1):
        e["id"] = f"E{i:05d}"

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    src_count = {}
    rules = set()
    for e in events:
        sev_count[e["severity"]] += 1
        src_count[e["source"]] = src_count.get(e["source"], 0) + 1
        if e["rule"]:
            rules.add(e["rule"])

    return {
        "events": events,
        "stats": {
            "total": len(events),
            "by_severity": sev_count,
            "by_source": src_count,
            "rules_fired": sorted(rules),
            "window": f"{(TODAY - timedelta(days=32)).isoformat()} ~ {TODAY.isoformat()}",
        },
    }
