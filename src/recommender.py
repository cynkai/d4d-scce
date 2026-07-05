#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
권고 생성기 — 활성 침해 업체에 '즉시 조치 권고 통보문'을 자동 생성.

기본은 템플릿 기반(오프라인 확정 동작). 현장 네트워크 없이도 데모가 돈다.
llm_summarize() 훅에 CMUX/LLM 을 연결하면 문장을 더 자연스럽게 다듬을 수 있다.
(선택 사항 — 없어도 완주 가능.)
"""

CATEGORY_KO = {
    "vpn": "VPN 원격접속",
    "sso": "SSO 통합인증",
    "admin_panel": "ERP/관리자 콘솔",
    "cloud_console": "클라우드 콘솔",
    "code_repo": "소스코드 저장소",
    "webmail": "웹메일",
    "saas": "SaaS 협업도구",
    "generic": "일반 포털",
}


def _fmt_categories(cats):
    return ", ".join(CATEGORY_KO.get(c, c) for c in cats)


def llm_summarize(context: dict) -> str | None:
    """
    CMUX/LLM 연결 지점. 반환 None 이면 템플릿 폴백.
    현장에서 파트너 API/자체 LLM 붙일 때만 구현. (지금은 미사용 = 오프라인 확정 동작)
    """
    return None


# 킬체인 단계별 조치 카탈로그 — 노출 계층에 맞춰 필요한 것만, 우선순위 순으로 선택된다.
_CONTAIN = "containment"
_ERAD = "eradication"
_RECOV = "recovery"
_INVEST = "investigation"

# 카테고리 → (조치문, 담당역할, 킬체인단계)
_CATEGORY_ACTIONS = {
    "vpn":           ("VPN 계정 비밀번호 초기화 + 활성 세션 강제 종료 + MFA 강제", "네트워크팀", _CONTAIN),
    "sso":           ("SSO/IdP 세션·리프레시토큰 폐기 + 재인증 강제", "IAM팀", _CONTAIN),
    "admin_panel":   ("ERP/관리자 콘솔 계정 잠금 + 권한 재검토", "시스템팀", _CONTAIN),
    "cloud_console": ("클라우드 콘솔 액세스키·세션 회수 + IAM 정책 감사", "클라우드팀", _CONTAIN),
    "code_repo":     ("코드저장소 토큰 폐기 + 최근 push/secret 유출 점검", "개발보안팀", _ERAD),
}


def _severity(vendor_rank: dict):
    """도달성·임무영향으로 심각도/SLA 산정. 반환: (등급, SLA분, 사유)."""
    reach = vendor_rank.get("reach", {})
    crit_kw = ("유도", "항공전자", "전술데이터", "통신", "시커", "FCS")
    mission_critical = any(k in vendor_rank.get("criticality", "") for k in crit_kw)
    if reach.get("full_chain"):
        return ("P1-CRITICAL", 60,
                "내부망 완결 경로(망 진입→신원→권한) 노출 — 추가 익스플로잇 없이 내부 자산 도달 가능")
    if reach.get("layers") and mission_critical:
        return ("P1-CRITICAL", 120,
                f"임무핵심 협력사 + 부분 도달({'·'.join(reach['layers'])})")
    if reach.get("layers"):
        return ("P2-HIGH", 240, f"부분 도달({'·'.join(reach['layers'])})")
    return ("P2-HIGH", 240, "활성 침해 확인(HIGH 크리덴셜 노출)")


def build_advisory(vendor_rank: dict) -> dict:
    """활성 침해 업체 1곳에 대한 통보문 초안 생성 (킬체인 우선순위 + SLA 정량화)."""
    incs = vendor_rank["active_incidents"]
    lead = max(incs, key=lambda x: (len(x["high_categories"]), -x["age_days"]))
    all_cats = sorted({c for i in incs for c in i["high_categories"]})
    reach = vendor_rank.get("reach", {})

    grade, sla_min, sla_reason = _severity(vendor_rank)
    sla_h = sla_min // 60

    title = f"[{grade}] {vendor_rank['name']} 활성 침해 정황 — 즉시 조치 권고"

    exec_line = (
        f"{vendor_rank['name']} {reach.get('label', '활성 침해')} — "
        f"{sla_h}시간 내 초동 조치 필요."
    )

    summary = (
        f"{vendor_rank['name']}({vendor_rank['criticality']}, "
        f"{vendor_rank['tier']}차 협력사) 소속 단말에서 "
        f"{lead['stealer_family']} 인포스틸러 감염이 확인되었으며, "
        f"{_fmt_categories(all_cats)} 자격증명이 평문으로 유출되었습니다. "
        f"도달성 판정: {reach.get('label', '-')}. "
        f"최근 감염({lead['age_days']}일 전)으로 '활성 침해' 상태이며, {sla_reason}."
    )

    # 킬체인 우선순위로 구조화된 조치 목록 생성
    ordered = []
    ordered.append({"stage": _CONTAIN, "owner": "IR팀", "priority": 1,
                    "action": f"감염 단말({lead['machine_id']}) 네트워크 격리 및 메모리/디스크 포렌식 확보"})
    # 노출 카테고리별 봉쇄 조치 (킬체인 단계 순 정렬)
    stage_order = {_CONTAIN: 0, _ERAD: 1, _RECOV: 2, _INVEST: 3}
    cat_actions = []
    for c in all_cats:
        if c in _CATEGORY_ACTIONS:
            text, owner, stage = _CATEGORY_ACTIONS[c]
            cat_actions.append({"stage": stage, "owner": owner, "action": text})
    cat_actions.sort(key=lambda a: stage_order[a["stage"]])
    for i, a in enumerate(cat_actions):
        ordered.append({**a, "priority": 2 + i})
    base_p = 2 + len(cat_actions)
    ordered.append({"stage": _INVEST, "owner": "IR팀", "priority": base_p,
                    "action": "노출 자격증명으로 접근 가능한 자산의 접근로그 30일 소급 조사"})
    ordered.append({"stage": _ERAD, "owner": "EDR팀", "priority": base_p + 1,
                    "action": f"{lead['stealer_family']} IOC 기반 사내 타 단말 감염 스윕"})
    ordered.append({"stage": _RECOV, "owner": "보안운영", "priority": base_p + 2,
                    "action": "원청 관제센터 동시 통보 + 협력사 계정 재사용 여부 전수 확인"})

    actions = [a["action"] for a in ordered]  # 하위호환(기존 필드 유지)

    notice = (
        f"수신: {vendor_rank['name']} 정보보호 담당 / 원청 보안관제센터\n"
        f"긴급도: {grade} · 초동 SLA: 접수 후 {sla_h}시간 이내\n"
        f"제목: {title}\n\n"
        f"{summary}\n\n"
        f"■ 탐지 근거\n"
        f"  - 스틸러: {lead['stealer_family']} (감염일 {lead['infection_date']}, {lead['age_days']}일 전)\n"
        f"  - 유출 자격증명 유형: {_fmt_categories(all_cats)}\n"
        f"  - 킬체인 도달성: {reach.get('label', '-')}\n"
        f"  - 활성 인시던트 수: {len(incs)}건\n\n"
        f"■ 즉시 조치 권고 (킬체인 봉쇄 우선순위)\n"
        + "\n".join(f"  {a['priority']}. [{_STAGE_KO.get(a['stage'], a['stage'])}·{a['owner']}] {a['action']}"
                    for a in ordered)
        + f"\n\n※ 본 통보는 자동 조기경보 결과이며, {grade} 기준 접수 후 {sla_h}시간 내 초동 조치를 권고합니다."
    )

    refined = llm_summarize({"summary": summary, "actions": actions})
    if refined:
        notice = refined

    return {
        "vendor_id": vendor_rank["vendor_id"],
        "title": title,
        "exec_summary": exec_line,
        "severity": grade,
        "sla_minutes": sla_min,
        "sla_reason": sla_reason,
        "reach_label": reach.get("label"),
        "summary": summary,
        "recommended_actions": actions,
        "structured_actions": ordered,
        "notice_draft": notice,
    }


_STAGE_KO = {
    "containment": "봉쇄",
    "eradication": "제거",
    "recovery": "복구",
    "investigation": "조사",
}
