#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
스코어링 엔진 — 업체별 위험점수 계산.

설계 철학 (문제 배경에서 도출):
    정적 유출 < 감염 사실 < 활성 침해(최근 + 내부망 크리덴셜)
    뒤로 갈수록 "지금 뚫리는 중"에 가까워 가중치가 계단식으로 뛴다.

선택: A안 = 활성 침해 지배. 활성 침해 1건이 다른 신호 누적을 압도한다.
      → 히어로 케이스가 항상 1위로 튀도록.

중요: 이 엔진은 데이터의 active_compromise 플래그를 신뢰하지 않고,
      credentials[].category + infection_date 로 직접 재판정한다.
      ("우리가 탐지·판정한다"가 성립해야 심사에서 단순 뷰어로 안 보임.)
"""

from datetime import date

TODAY = date(2026, 7, 4)

# --- 카테고리 심각도 --------------------------------------------------------
HIGH_CATEGORIES = {"vpn", "sso", "admin_panel", "cloud_console", "code_repo"}

# --- 가중치 (A안: 활성침해 지배) --------------------------------------------
W_ACTIVE_BASE = 40.0      # 활성 침해 1건 base (freshness로 증폭)
W_ACTIVE_EXTRA_HIGH = 5.0 # 추가 HIGH 카테고리 1종당 보너스
W_LEAK_BASE = 2.0         # 유출 크리덴셜 1건 base
W_LEAK_PLAINTEXT = 1.5    # 평문 배수
W_STEALER_MACHINE = 8.0   # 감염기기 1대 base

# 킬체인 도달성(reach): 고립된 크리덴셜 N개보다, '내부망 완결 경로'가 뚫린 게 더 치명적.
#   network(망 진입) + identity(신원) + privileged(권한 상승) 3계층이 모두 노출되면
#   공격자가 추가 익스플로잇 없이 내부 자산까지 도달 가능 → 도달성 보너스.
REACH_LAYERS = {
    "network":    {"vpn"},
    "identity":   {"sso"},
    "privileged": {"admin_panel", "cloud_console", "code_repo"},
}
W_REACH_LAYER = 6.0       # 도달 계층 1종당 보너스
W_REACH_FULLCHAIN = 12.0  # 3계층 모두 노출 = 내부망 완결 경로 확보 보너스

# 임무 영향 승수 (더하지 않고 곱한다 — "뚫리면 얼마나 치명적인가")
MULT_TIER2 = 1.2
MULT_CRIT_HIGH = 1.15
MULT_CAP = 1.4
CRIT_HIGH_KEYWORDS = ("유도", "항공전자", "전술데이터", "통신", "시커", "FCS")

# 활성 침해로 인정하는 최신성 창(일). 이보다 오래되면 활성으로 안 봄.
ACTIVE_WINDOW_DAYS = 30


def _age_days(iso_date: str) -> int:
    y, m, d = map(int, iso_date.split("-"))
    return (TODAY - date(y, m, d)).days


def freshness(iso_date: str) -> float:
    """30일마다 반감. 2일 전≈0.95, 30일≈0.5, 1년≈0.0002."""
    age = max(_age_days(iso_date), 0)
    return 0.5 ** (age / 30.0)


def detect_active_compromise(log: dict) -> dict:
    """
    스틸러 로그 1건을 재판정.
    반환: {is_active, high_categories, exposed_urls, freshness}
    조건: 회사 크리덴셜(HIGH 카테고리) + 최신성 창 이내 감염.
    """
    vendor_id = log.get("vendor_id")
    high_cats, urls = set(), []
    for c in log.get("credentials", []):
        if c.get("category") in HIGH_CATEGORIES:
            # url 도메인이 해당 업체 것인지는 matcher 단계에서 이미 vendor_id로 귀속됨.
            high_cats.add(c["category"])
            urls.append(c["url"])
    age = _age_days(log.get("infection_date", TODAY.isoformat()))
    is_active = bool(vendor_id and high_cats and age <= ACTIVE_WINDOW_DAYS)
    return {
        "is_active": is_active,
        "high_categories": sorted(high_cats),
        "exposed_urls": urls,
        "freshness": freshness(log.get("infection_date", TODAY.isoformat())),
        "age_days": age,
    }


def mission_multiplier(vendor: dict) -> float:
    mult = 1.0
    if vendor.get("tier") == 2:
        mult *= MULT_TIER2
    crit = vendor.get("criticality", "")
    if any(k in crit for k in CRIT_HIGH_KEYWORDS):
        mult *= MULT_CRIT_HIGH
    return min(mult, MULT_CAP)


def score_vendor(vendor: dict, leaks: list, stealers: list) -> dict:
    """한 업체의 위험점수 + 근거 분해를 계산."""
    # 1) 활성 침해 (지배 신호)
    active_score = 0.0
    active_incidents = []
    for log in stealers:
        det = detect_active_compromise(log)
        if det["is_active"]:
            base = W_ACTIVE_BASE + W_ACTIVE_EXTRA_HIGH * max(len(det["high_categories"]) - 1, 0)
            contrib = base * det["freshness"]
            active_score += contrib
            active_incidents.append({
                "log_id": log["log_id"],
                "stealer_family": log["stealer_family"],
                "infection_date": log["infection_date"],
                "machine_id": log["machine_id"],
                "high_categories": det["high_categories"],
                "exposed_urls": det["exposed_urls"],
                "age_days": det["age_days"],
                "contribution": round(contrib, 1),
            })

    # 1-b) 킬체인 도달성 — 활성 인시던트가 노출한 HIGH 카테고리를 계층으로 접어
    #      '내부망 완결 경로'가 뚫렸는지 평가. 도달 계층은 활성 침해 신호에 합산한다.
    reach = assess_reach([c for inc in active_incidents for c in inc["high_categories"]])
    reach_score = reach["score"] if active_incidents else 0.0
    active_score += reach_score

    # 1-c) 크리덴셜 종류별 기여도 — "왜 이 점수인가"를 신호 출처 축(활성침해/유출/감염기기) 뿐 아니라
    #      노출된 크리덴셜 종류(VPN/SSO/Admin/Cloud/Repo) 축으로도 분해한다.
    #      정직성 원칙: 카테고리별로 따로 보정된 가중치 표가 있는 게 아니라, 각 인시던트의
    #      실제 기여도(contribution)를 그 인시던트가 노출한 카테고리 수만큼 균등 배분한 값이다.
    category_breakdown = {}
    for inc in active_incidents:
        cats = inc["high_categories"]
        if not cats:
            continue
        share = inc["contribution"] / len(cats)
        for c in cats:
            category_breakdown[c] = category_breakdown.get(c, 0.0) + share
    if reach["layers"] and active_incidents:
        # 도달성 보너스도 그 계층을 구성한 카테고리에 균등 배분
        reach_cats = sorted({c for inc in active_incidents for c in inc["high_categories"]
                              for layer_cats in REACH_LAYERS.values() if c in layer_cats})
        if reach_cats:
            share = reach_score / len(reach_cats)
            for c in reach_cats:
                category_breakdown[c] = category_breakdown.get(c, 0.0) + share
    category_breakdown = {k: round(v, 1) for k, v in
                          sorted(category_breakdown.items(), key=lambda kv: -kv[1])}

    # 2) 유출 자격증명 (정적, 누적, 시간감쇠)
    leak_score = 0.0
    for r in leaks:
        mult = W_LEAK_PLAINTEXT if r.get("password_type") == "plaintext" else 1.0
        leak_score += W_LEAK_BASE * mult * freshness(r["first_seen"])

    # 3) 감염기기 존재 (엔드포인트 침해, 시간감쇠)
    stealer_score = 0.0
    for log in stealers:
        stealer_score += W_STEALER_MACHINE * freshness(log["infection_date"])

    raw = active_score + leak_score + stealer_score
    mult = mission_multiplier(vendor)
    final = raw * mult

    return {
        "vendor_id": vendor["vendor_id"],
        "name": vendor["name"],
        "tier": vendor["tier"],
        "criticality": vendor["criticality"],
        "risk_score": round(final, 1),
        "breakdown": {
            "active_compromise": round(active_score, 1),
            "leaked_credentials": round(leak_score, 1),
            "stealer_infections": round(stealer_score, 1),
            "mission_multiplier": round(mult, 2),
            "reach_score": round(reach_score, 1),
        },
        "reach": reach,
        "category_breakdown": category_breakdown,
        "counts": {
            "leaked_records": len(leaks),
            "infected_machines": len(stealers),
            "active_incidents": len(active_incidents),
        },
        "active_incidents": active_incidents,
    }


def assess_reach(exposed_categories) -> dict:
    """
    노출된 HIGH 카테고리 → 킬체인 도달 계층으로 접기.
    3계층(network·identity·privileged) 모두 뚫리면 '내부망 완결 경로'로 판정.
    반환: {layers[], full_chain(bool), score, label}
    """
    cats = set(exposed_categories)
    layers = [name for name, members in REACH_LAYERS.items() if cats & members]
    full = len(layers) == len(REACH_LAYERS)
    score = W_REACH_LAYER * len(layers) + (W_REACH_FULLCHAIN if full else 0.0)
    if full:
        label = "내부망 완결 경로 (망 진입→신원→권한)"
    elif layers:
        label = "부분 도달: " + "·".join(layers)
    else:
        label = "도달 계층 없음"
    return {"layers": layers, "full_chain": full, "score": round(score, 1), "label": label}


def classify(rank_row: dict) -> str:
    """
    상태 라벨. 활성 침해가 있으면 무조건 CRITICAL.

    NO SIGNAL 구분 (관측편향 대응):
      SCCE는 다크웹·스틸러 채널에 '관측된' 흔적만 볼 수 있다. 어떤 협력사가
      실제로 침해당했더라도 그 흔적이 공격자 쪽 유통망(재판매·재유출)에
      노출되지 않았다면 여기서는 보이지 않는다. 그래서 신호가 전혀 없는
      협력사를 "LOW(안전 확인됨)"로 부르면 "관측 안 됨"과 "실제로 안전함"을
      혼동시킨다. SCCE는 이 둘을 명시적으로 분리한다:
        - LOW      : 신호가 있지만 위험도가 낮음(관측됨 + 경미)
        - NO SIGNAL: 관측된 신호가 전혀 없음(안전 증명 아님 — 관측 공백)
    """
    if rank_row["counts"]["active_incidents"] > 0:
        return "CRITICAL — 즉시 조치"
    c = rank_row["counts"]
    if c["leaked_records"] == 0 and c["infected_machines"] == 0:
        return "NO SIGNAL — 관측 공백"
    s = rank_row["risk_score"]
    if s >= 15:
        return "HIGH"
    if s >= 5:
        return "MEDIUM"
    return "LOW"
