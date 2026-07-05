#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IOC 추출 — raw 신호에서 침해지표(Indicators of Compromise)를 정규화 추출.
분석관이 바로 차단/헌팅에 넣을 수 있는 형태. (deployability↑)
"""

import re
from urllib.parse import urlparse

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _ioc_type(host: str) -> str:
    return "ipv4" if IP_RE.match(host) else "domain"


def extract(stealers: list) -> list:
    """전체 스틸러 로그에서 IOC 집계. type/value/context/count/first_seen."""
    table = {}

    def bump(itype, value, ctx, seen):
        key = (itype, value)
        if key not in table:
            table[key] = {"type": itype, "value": value, "context": ctx,
                          "count": 0, "first_seen": seen}
        table[key]["count"] += 1
        if seen < table[key]["first_seen"]:
            table[key]["first_seen"] = seen

    for log in stealers:
        seen = log.get("infection_date", "9999-99-99")
        c2 = log.get("c2_host")
        if c2:
            bump(_ioc_type(c2), c2, "stealer C2/exfil", seen)
        fam = log.get("stealer_family")
        if fam:
            bump("malware_family", fam, "infostealer", seen)
        actor = log.get("threat_actor")
        if actor:
            bump("threat_actor", actor, "attribution", seen)
    return sorted(table.values(), key=lambda x: (-x["count"], x["type"]))


def vendor_iocs(stealer_logs: list) -> dict:
    """한 업체 범위 IOC (드릴다운용)."""
    c2 = sorted({l["c2_host"] for l in stealer_logs if l.get("c2_host")})
    fams = sorted({l["stealer_family"] for l in stealer_logs if l.get("stealer_family")})
    machines = [l["machine_id"] for l in stealer_logs]
    return {"c2_hosts": c2, "stealer_families": fams, "machines": machines}
