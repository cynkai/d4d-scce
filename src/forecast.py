#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
확산 예측 엔진 — '다음에 뚫릴 협력사'를 미리 지목한다.

조기경보의 완성: 지금까지는 이미 발생한 침해를 얼마나 빨리 봤나(회고적)였다면,
이 모듈은 캠페인의 표적 프로파일 + 각 협력사의 사전 노출 신호를 결합해
아직 활성 침해가 아닌 협력사 중 '다음 표적 확산 가능성'을 정량화한다.

주의(정직성): 이것은 확정 예측이 아니라 다중 신호 기반 휴리스틱 우선순위다.
             근거(reasons)를 함께 제시해 분석관이 검증 가능하게 한다.
"""

from datetime import date

TODAY = date(2026, 7, 4)


def _age(iso):
    try:
        y, m, d = map(int, iso.split("-"))
        return (TODAY - date(y, m, d)).days
    except Exception:
        return 9999


def _tokens(criticality: str):
    """공급 품목 문자열에서 표적 프로파일 토큰 추출."""
    import re
    return set(t for t in re.split(r"[\s/()·,]+", criticality or "") if len(t) >= 2)


def predict_next_targets(vendors, ranked, campaigns, leaks_by_v, stealers_by_v,
                         cross_links, lookalikes, top_n=5):
    """
    반환: {primary_campaign, spread, predictions[]}
      predictions[]: {vendor, escalation_risk(0~100), band, reasons[], projected_window}
    """
    if not campaigns:
        return {"primary_campaign": None, "spread": None, "predictions": []}

    primary = campaigns[0]
    hit_ids = {a["vendor_id"] for a in primary["affected_vendors"]}
    rank_by_id = {r["vendor_id"]: r for r in ranked}
    vendor_by_id = {v["vendor_id"]: v for v in vendors}

    # 캠페인 표적 프로파일 (이미 뚫린 업체들에서 학습)
    hit_tier = {}
    hit_tokens = set()
    for vid in hit_ids:
        v = vendor_by_id.get(vid)
        if not v:
            continue
        hit_tier[v["tier"]] = hit_tier.get(v["tier"], 0) + 1
        hit_tokens |= _tokens(v.get("criticality", ""))
    majority_tier = max(hit_tier, key=hit_tier.get) if hit_tier else None

    # 확산 속도 + 다음 감염 투영일
    span = max(primary.get("span_days", 0), 1)
    cnt = max(primary.get("affected_count", 1), 1)
    per_day = cnt / span
    mean_interval = span / max(cnt - 1, 1)
    last_seen = primary.get("last_seen")
    proj_days = round(mean_interval)
    projected_window = None
    if last_seen:
        try:
            y, m, d = map(int, last_seen.split("-"))
            from datetime import timedelta
            projected_window = (date(y, m, d) + timedelta(days=proj_days)).isoformat()
        except Exception:
            pass

    # 이미 뚫린 업체와 자격증명/단말을 공유하는 업체 = 횡적 경로 존재
    linked_to_hit = {}
    for link in cross_links:
        vids = set(link.get("vendor_ids", []))
        if vids & hit_ids:
            for vid in vids - hit_ids:
                linked_to_hit.setdefault(vid, []).append(link)

    lookalike_targets = {l["mimics_vendor_id"] for l in lookalikes}

    predictions = []
    for v in vendors:
        vid = v["vendor_id"]
        if vid in hit_ids:
            continue  # 이미 캠페인에 포함
        row = rank_by_id.get(vid, {})
        if row.get("counts", {}).get("active_incidents", 0) > 0:
            continue  # 이미 활성 침해(=이미 표적) → '다음'이 아님

        score = 0.0
        reasons = []

        # 1) 이미 뚫린 업체와 자격증명/단말 공유 (가장 강한 신호)
        if vid in linked_to_hit:
            score += 34
            n = len(linked_to_hit[vid])
            reasons.append(f"캠페인 피해사와 자격증명/단말 공유 {n}건 — 횡적 이동 경로 존재")

        # 2) 표적 품목 프로파일 일치
        overlap = _tokens(v.get("criticality", "")) & hit_tokens
        if overlap:
            score += min(10 + 6 * len(overlap), 24)
            reasons.append(f"표적 품목군 일치({'·'.join(sorted(overlap))})")

        # 3) 말단(2차) 협력사 = APT 공급망 진입 선호 (문제 배경)
        if v.get("tier") == 2:
            score += 12
            reasons.append("2차 말단 협력사 — 공급망 진입점 선호 표적")
        if majority_tier is not None and v.get("tier") == majority_tier:
            score += 6
            reasons.append(f"캠페인 주(主) 표적 계층({majority_tier}차)과 동일")

        # 4) 사전 노출: 유출 자격증명 존재 (사전 정찰/발판)
        lk = leaks_by_v.get(vid, [])
        recent_leak = any(_age(x.get("first_seen", "")) <= 60 for x in lk)
        if recent_leak:
            score += 10
            reasons.append("최근 60일 내 유출 자격증명 관측 — 사전 정찰 정황")
        elif lk:
            score += 4
            reasons.append("과거 유출 자격증명 누적")

        # 5) 비활성 스틸러 발판 (아직 HIGH 아님이지만 단말 감염 존재)
        if stealers_by_v.get(vid):
            score += 8
            reasons.append("비활성 스틸러 감염 발판 존재")

        # 6) 사칭(룩얼라이크) 도메인 표적
        if vid in lookalike_targets:
            score += 14
            reasons.append("협력사 사칭 도메인 관측 — 능동적 피싱 준비 정황")

        if score <= 0:
            continue
        score = min(round(score), 100)
        band = "HIGH" if score >= 45 else ("MEDIUM" if score >= 25 else "LOW")
        predictions.append({
            "vendor_id": vid,
            "name": v["name"],
            "tier": v["tier"],
            "criticality": v.get("criticality", ""),
            "escalation_risk": score,
            "band": band,
            "reasons": reasons,
            "projected_window": projected_window,
        })

    predictions.sort(key=lambda p: -p["escalation_risk"])
    return {
        "primary_campaign": primary["campaign_id"],
        "spread": {
            "affected_count": cnt,
            "span_days": span,
            "vendors_per_day": round(per_day, 2),
            "mean_interval_days": round(mean_interval, 1),
            "projected_next_hit": projected_window,
            "note": f"확산 속도 {round(per_day, 2)}개사/일 · 평균 {round(mean_interval, 1)}일 간격",
        },
        "predictions": predictions[:top_n],
    }
