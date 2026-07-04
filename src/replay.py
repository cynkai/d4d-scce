#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
조기경보 리플레이 엔진 v2 — 일자별 as-of 스냅샷.

핵심 서사(정직하게):
  히어로(태성회로 = crown-jewel)를 실제로 뚫은 '그 캠페인'을 특정하고,
  그 캠페인이 ≥2개 협력사에서 탐지 가능해진 첫날(=조기경보일)이
  crown-jewel 정점 침해보다 며칠 앞서는지 = 조기경보 '리드타임'.

즉 배경 노이즈가 아니라 '우리를 뚫은 그 작전'을 언제 먼저 봤는가.
"""

from datetime import date, timedelta

TODAY = date(2026, 7, 4)
ACTIVE_WINDOW = 30
HIGH = {"vpn", "sso", "admin_panel", "cloud_console", "code_repo"}
CROWN_JEWEL = "태성회로"


def _d(iso):
    y, m, dd = map(int, iso.split("-"))
    return date(y, m, dd)


def _primary_campaign(stealers, vendors):
    """crown-jewel 을 포함하고 ≥2개 협력사를 가진 (family, c2) 그룹 = 주(主) 캠페인."""
    vid_of = {v["name"]: v["vendor_id"] for v in vendors}
    cj = vid_of.get(CROWN_JEWEL)
    groups = {}
    for log in stealers:
        if log.get("vendor_id") and log.get("c2_host"):
            groups.setdefault((log["stealer_family"], log["c2_host"]), set()).add(log["vendor_id"])
    best = None
    for key, vids in groups.items():
        if cj in vids and len(vids) >= 2:
            if best is None or len(vids) > len(groups[best]):
                best = key
    return best  # (family, c2) or None


def build_replay(vendors, leaks, stealers, days=32):
    vname = {v["vendor_id"]: v["name"] for v in vendors}
    primary = _primary_campaign(stealers, vendors)
    prim_logs = [l for l in stealers
                 if primary and (l.get("stealer_family"), l.get("c2_host")) == primary
                 and l.get("vendor_id")]

    start = TODAY - timedelta(days=days)
    snaps, ew_day, hero_peak = [], None, None

    for i in range(days + 1):
        d = start + timedelta(days=i)
        L = [x for x in leaks if _d(x["first_seen"]) <= d]
        S = [x for x in stealers if _d(x["infection_date"]) <= d]

        # as-of 활성 침해(전체)
        active = []
        for log in S:
            if not log.get("vendor_id"):
                continue
            if _d(log["infection_date"]) < d - timedelta(days=ACTIVE_WINDOW):
                continue
            if {c["category"] for c in log.get("credentials", [])} & HIGH:
                active.append(log)

        # 주 캠페인 as-of 확산 (걸린 협력사 수)
        prim_vendors = {l["vendor_id"] for l in prim_logs if _d(l["infection_date"]) <= d}
        prim_count = len(prim_vendors)
        campaign_detected = prim_count >= 2
        if campaign_detected and ew_day is None:
            ew_day = d.isoformat()

        # crown-jewel 정점(활성 침해 처음 걸린 날)
        if hero_peak is None and any(vname.get(l.get("vendor_id")) == CROWN_JEWEL for l in active):
            hero_peak = d.isoformat()

        # 위험 지수(리플레이 시각화용): 활성 + 주캠페인 확산이 주도, 배경은 소량
        risk = len(active) * 45 + prim_count * 18 + len(S) * 0.8
        if hero_peak == d.isoformat() or (campaign_detected and len(active) >= 2):
            status = "critical"
        elif campaign_detected or active:
            status = "warning"
        elif S:
            status = "elevated"
        else:
            status = "nominal"

        # 당일 이벤트(티커)
        events = []
        for log in S:
            if log["infection_date"] == d.isoformat() and log.get("vendor_id"):
                is_prim = primary and (log.get("stealer_family"), log.get("c2_host")) == primary
                cats = sorted({c["category"] for c in log.get("credentials", []) if c["category"] in HIGH})
                events.append({
                    "kind": "stealer",
                    "label": f"{vname.get(log['vendor_id'], log['vendor_id'])} · {log['stealer_family']} 감염"
                             + (f" (HIGH: {', '.join(cats)})" if cats else ""),
                    "campaign": bool(is_prim),
                })
        leak_today = sum(1 for x in L if x["first_seen"] == d.isoformat() and x.get("vendor_id"))
        if leak_today:
            events.append({"kind": "leak", "label": f"협력사 자격증명 유출 {leak_today}건", "campaign": False})

        snaps.append({
            "date": d.isoformat(),
            "exposed_credentials": len(L),
            "infected_machines": len(S),
            "active_compromises": len(active),
            "campaign_spread": prim_count,
            "campaign_detected": campaign_detected,
            "risk_index": round(risk, 1),
            "status": status,
            "events": events[:4],
        })

    lead = (_d(hero_peak) - _d(ew_day)).days if (ew_day and hero_peak) else None
    return {
        "snapshots": snaps,
        "early_warning_day": ew_day,
        "hero_peak_day": hero_peak,
        "lead_days": lead,
        "window_days": days,
        "primary_campaign": {"stealer_family": primary[0], "c2_host": primary[1]} if primary else None,
        "crown_jewel": CROWN_JEWEL,
    }
