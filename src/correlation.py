#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
상관 엔진 — 여러 협력사에 걸친 '조율된 공급망 캠페인'을 탐지한다.

이게 이 프로젝트의 핵심 차별점.
개별 업체 점수 12개가 아니라, "같은 스틸러 + 같은 C2 + 같은 시간창"으로
다수 협력사를 동시 타격한 공격을 하나의 캠페인으로 묶어 보여준다.
→ "이건 우연한 개별 유출이 아니라 공급망을 노린 조율된 작전이다"라는 서사.

또한 대시보드용 관계 그래프(nodes/edges)를 생성한다.
"""

from datetime import date

TODAY = date(2026, 7, 4)
WINDOW_DAYS = 14  # 캠페인으로 묶는 시간창


def _age(iso):
    y, m, d = map(int, iso.split("-"))
    return (TODAY - date(y, m, d)).days


def detect_campaigns(stealers: list, vendors: list) -> list:
    """
    (stealer_family, c2_host) 별로 로그를 묶고,
    2개 이상 서로 다른 협력사가 시간창 안에서 걸리면 캠페인으로 인정.
    """
    vname = {v["vendor_id"]: v["name"] for v in vendors}
    groups = {}
    for log in stealers:
        c2 = log.get("c2_host")
        vid = log.get("vendor_id")
        if not (c2 and vid):
            continue
        key = (log.get("stealer_family"), c2)
        groups.setdefault(key, []).append(log)

    campaigns = []
    for (family, c2), logs in groups.items():
        vids = {l["vendor_id"] for l in logs}
        if len(vids) < 2:
            continue
        dates = [l["infection_date"] for l in logs]
        span = max(_age(min(dates)), 0) - max(_age(max(dates)), 0)
        if span > WINDOW_DAYS * 3:  # 너무 흩어져 있으면 캠페인 아님
            continue
        actor = next((l.get("threat_actor") for l in logs if l.get("threat_actor")), None)
        campaign_id = next((l.get("campaign_id") for l in logs if l.get("campaign_id")),
                           f"CAMP-{family}-{c2[:6]}")
        # 신뢰도: 걸린 업체 수 + 시간 밀집 + 명시적 태그
        conf = min(0.5 + 0.12 * len(vids) + (0.15 if span <= WINDOW_DAYS else 0), 0.97)
        campaigns.append({
            "campaign_id": campaign_id,
            "stealer_family": family,
            "c2_host": c2,
            "threat_actor": actor,
            "affected_vendors": [{"vendor_id": v, "name": vname.get(v, v)} for v in sorted(vids)],
            "affected_count": len(vids),
            "machines": [l["machine_id"] for l in logs],
            "first_seen": min(dates),
            "last_seen": max(dates),
            "span_days": span,
            "confidence": round(conf, 2),
            "note": (f"{len(vids)}개 협력사가 동일 C2({c2})·동일 스틸러({family})로 "
                     f"{span}일 내 동시 감염 — 조율된 공급망 표적 정황."),
        })
    return sorted(campaigns, key=lambda c: (-c["affected_count"], -c["confidence"]))


def build_graph(vendors, ranked, campaigns) -> dict:
    """
    관계 그래프. 노드: 캠페인/행위자/C2/협력사. 엣지: 소속·사용·타격.
    대시보드가 SVG force-lite 로 그린다.
    """
    nodes, edges, seen = [], [], set()

    def node(nid, ntype, label, extra=None):
        if nid in seen:
            return
        seen.add(nid)
        n = {"id": nid, "type": ntype, "label": label}
        if extra:
            n.update(extra)
        nodes.append(n)

    score = {r["vendor_id"]: r["risk_score"] for r in ranked}
    status = {r["vendor_id"]: r["status"] for r in ranked}

    for c in campaigns:
        cid = c["campaign_id"]
        node(cid, "campaign", cid, {"confidence": c["confidence"]})
        if c.get("threat_actor"):
            aid = f"actor:{c['threat_actor']}"
            node(aid, "actor", c["threat_actor"])
            edges.append({"source": aid, "target": cid, "rel": "operates"})
        c2id = f"c2:{c['c2_host']}"
        node(c2id, "c2", c["c2_host"])
        edges.append({"source": cid, "target": c2id, "rel": "uses"})
        for v in c["affected_vendors"]:
            vid = v["vendor_id"]
            node(vid, "vendor", v["name"],
                 {"risk": score.get(vid, 0), "status": status.get(vid, "LOW")})
            edges.append({"source": cid, "target": vid, "rel": "hits"})
    return {"nodes": nodes, "edges": edges}
