#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK 매핑 — 관측된 신호를 ATT&CK 기법으로 매핑한다.
CTI 신뢰성의 핵심. 심사에서 "단순 대시보드"가 아니라 "위협 분석"으로 보이게 함.
"""

# 카테고리/신호 → ATT&CK 기법
CATEGORY_TECHNIQUES = {
    "vpn":           [("T1133", "External Remote Services"),
                      ("T1078", "Valid Accounts")],
    "sso":           [("T1078", "Valid Accounts"),
                      ("T1556", "Modify Authentication Process")],
    "admin_panel":   [("T1078.004", "Valid Accounts: Cloud Accounts"),
                      ("T1190", "Exploit Public-Facing Application")],
    "cloud_console": [("T1078.004", "Valid Accounts: Cloud Accounts"),
                      ("T1538", "Cloud Service Dashboard")],
    "code_repo":     [("T1213.003", "Data from Code Repositories"),
                      ("T1195.001", "Supply Chain Compromise: Dev Tools")],
    "webmail":       [("T1114", "Email Collection")],
    "saas":          [("T1213", "Data from Information Repositories")],
    "generic":       [("T1078", "Valid Accounts")],
}

# 스틸러 감염 자체가 함의하는 기법
STEALER_TECHNIQUES = [
    ("T1555", "Credentials from Password Stores"),
    ("T1539", "Steal Web Session Cookie"),
    ("T1005", "Data from Local System"),
]

# 공급망 문맥
SUPPLYCHAIN_TECHNIQUE = ("T1195.002", "Compromise Software Supply Chain")


def map_vendor(vendor_rank: dict) -> list:
    """한 업체의 활성 인시던트에서 관측된 기법 목록(중복 제거, 카운트)."""
    counter = {}

    def add(tid, name):
        counter[tid] = {"technique_id": tid, "name": name,
                        "count": counter.get(tid, {}).get("count", 0) + 1}

    for inc in vendor_rank.get("active_incidents", []):
        for tid, name in STEALER_TECHNIQUES:
            add(tid, name)
        for cat in inc.get("high_categories", []):
            for tid, name in CATEGORY_TECHNIQUES.get(cat, []):
                add(tid, name)
    if vendor_rank.get("active_incidents"):
        add(*SUPPLYCHAIN_TECHNIQUE)
    return sorted(counter.values(), key=lambda x: (-x["count"], x["technique_id"]))


def summarize(ranked: list) -> list:
    """전체 관측 기법 요약 (대시보드 MITRE 패널용)."""
    agg = {}
    for r in ranked:
        for t in r.get("mitre", []):
            if t["technique_id"] not in agg:
                agg[t["technique_id"]] = {"technique_id": t["technique_id"],
                                          "name": t["name"], "count": 0}
            agg[t["technique_id"]]["count"] += t["count"]
    return sorted(agg.values(), key=lambda x: (-x["count"], x["technique_id"]))
