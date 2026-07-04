#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
매처 — 유출·스틸러 신호를 협력사 도메인/자산에 상관(correlate)시킨다.

원칙: 데이터에 미리 붙은 vendor_id 를 신뢰하지 않고, 도메인으로 직접 귀속한다.
      ("우리가 상관분석한다"가 성립해야 함.)

고도화(branch 1·2):
  - 라벨 서픽스 인덱스로 O(라벨수) 귀속 (선형 스캔 제거) + www 정규화.
  - 룩얼라이크(타이포스쿼팅) 탐지: 협력사 도메인과 edit-distance 1 인 유사 도메인을
    별도 신호로 표시 (APT가 방산 협력사 사칭 도메인을 등록하는 정황).
  - 매칭 방법(match_method) 기록으로 근거 추적성 확보.
  - 자격증명 재사용 링크: 같은 계정이 여러 협력사에, 또는 한 감염 단말이 여러 협력사에
    걸리는 '공급망 횡단' 신호를 별도 산출.
"""

from urllib.parse import urlparse


# ---- 도메인 인덱스 --------------------------------------------------------
def build_domain_index(vendors: list) -> dict:
    """
    도메인 -> vendor 매핑.
    exact(정확·서브도메인) 귀속을 위한 dict + 룩얼라이크 비교용 도메인 목록을 함께 담는다.
    """
    exact = {}
    known = []
    for v in vendors:
        for d in v.get("domains", []):
            dl = _norm_host(d)
            exact[dl] = v
            known.append((dl, v))
    return {"exact": exact, "known": known}


def _norm_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _domain_of_email(email: str) -> str:
    return _norm_host(email.split("@")[-1]) if "@" in (email or "") else ""


def _domain_of_url(url: str) -> str:
    return _norm_host(urlparse(url).hostname or "")


def _resolve_exact(host: str, idx: dict):
    """host 가 어떤 vendor 도메인의 자신 또는 서브도메인이면 (vendor, method) 반환."""
    if not host:
        return None, None
    exact = idx["exact"]
    if host in exact:
        return exact[host], "exact"
    # 라벨 서픽스: a.b.vendor.co.kr → vendor.co.kr 까지 접미어를 좁혀가며 조회
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        suffix = ".".join(labels[i:])
        if suffix in exact:
            return exact[suffix], "subdomain"
    return None, None


def _typo_match(a: str, b: str) -> bool:
    """
    타이포스쿼팅 판정: 편집거리 1(치환/삽입/삭제) 또는 인접 전치(swap) 1회.
    전치(pcb→pbc)는 Levenshtein으로는 거리 2이지만 대표적 오타 사칭 유형이라 포함(Damerau).
    """
    if a == b:
        return False  # 동일은 사칭 아님
    la, lb = len(a), len(b)
    # 인접 전치 1회 (같은 길이)
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1 and sum(1 for x, y in zip(a, b) if x != y) == 1:
            return True  # 치환 1회
        if len(diff) == 2 and diff[1] == diff[0] + 1 \
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]:
            return True  # 인접 전치 1회
        return False
    if abs(la - lb) != 1:
        return False
    # 삽입/삭제 1회: 짧은 쪽이 긴 쪽에서 한 글자 뺀 것과 같은지
    if la > lb:
        a, b = b, a
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1; j += 1
        elif skipped:
            return False
        else:
            skipped = True; j += 1
    return True


def _lookalike_of(host: str, idx: dict):
    """host 가 어떤 협력사 도메인의 룩얼라이크(오타/사칭)면 그 vendor 반환, 아니면 None."""
    if not host or "." not in host:
        return None
    reg = host.split(".")[0]  # 최상위 라벨(회사명 부분)만 비교
    for dl, v in idx["known"]:
        if host == dl:
            return None  # 정확 일치는 룩얼라이크 아님
        vreg = dl.split(".")[0]
        # 회사명 라벨이 오타/전치로 사칭된 경우
        if len(reg) >= 4 and _typo_match(reg, vreg):
            return v
    return None


# ---- 매칭 -----------------------------------------------------------------
def match_leaks(leaks: list, idx: dict) -> dict:
    """vendor_id -> [leaked records]. 정확/서브도메인 귀속. 매칭 안 되면 버림(노이즈)."""
    out = {}
    for r in leaks:
        host = _domain_of_email(r["email"])
        v, method = _resolve_exact(host, idx)
        if v:
            r = dict(r, vendor_id=v["vendor_id"], match_method=method)
            out.setdefault(v["vendor_id"], []).append(r)
    return out


def match_stealers(stealers: list, idx: dict) -> dict:
    """
    vendor_id -> [stealer logs].
    각 로그의 credentials 중 회사 도메인에 걸리는 것만 남겨 재구성하고,
    그 로그를 해당 vendor 로 귀속.
    """
    out = {}
    for log in stealers:
        vendor_creds = {}
        for c in log.get("credentials", []):
            v, method = _resolve_exact(_domain_of_url(c["url"]), idx)
            if v:
                vendor_creds.setdefault(v["vendor_id"], []).append(dict(c, match_method=method))
        for vid, creds in vendor_creds.items():
            scoped = dict(log, vendor_id=vid, credentials=creds)
            out.setdefault(vid, []).append(scoped)
    return out


# ---- branch 1: 룩얼라이크(사칭 도메인) 탐지 -------------------------------
def detect_lookalikes(leaks: list, stealers: list, idx: dict) -> list:
    """
    협력사 도메인을 사칭한 룩얼라이크 도메인을 신호에서 수집.
    반환: [{lookalike, mimics_vendor, mimics_domain, seen_in, count}]
    """
    hits = {}

    def record(host, vendor, kind):
        if not host:
            return
        target = _lookalike_of(host, idx)
        if not target or target["vendor_id"] != vendor["vendor_id"]:
            return
        key = (host, vendor["vendor_id"])
        rec = hits.setdefault(key, {
            "lookalike": host,
            "mimics_vendor": vendor["name"],
            "mimics_vendor_id": vendor["vendor_id"],
            "seen_in": set(),
            "count": 0,
        })
        rec["seen_in"].add(kind)
        rec["count"] += 1

    # 룩얼라이크는 매칭 안 된(=vendor 귀속 실패) 도메인에서 찾는다
    for r in leaks:
        host = _domain_of_email(r.get("email", ""))
        v, _ = _resolve_exact(host, idx)
        if not v:
            tgt = _lookalike_of(host, idx)
            if tgt:
                record(host, tgt, "leak")
    for log in stealers:
        for c in log.get("credentials", []):
            host = _domain_of_url(c.get("url", ""))
            v, _ = _resolve_exact(host, idx)
            if not v:
                tgt = _lookalike_of(host, idx)
                if tgt:
                    record(host, tgt, "stealer")

    out = []
    for rec in hits.values():
        rec["seen_in"] = sorted(rec["seen_in"])
        out.append(rec)
    return sorted(out, key=lambda x: -x["count"])


# ---- branch 2: 자격증명 재사용 / 공급망 횡단 링크 -------------------------
def _identity_of(cred_or_leak) -> str:
    """계정 식별자 정규화 (email 우선, 없으면 username 로컬파트)."""
    val = cred_or_leak.get("email") or cred_or_leak.get("username") or ""
    val = val.strip().lower()
    return val.split("@")[0] if "@" in val else val


def link_identities(leaks_by_v: dict, stealers_by_v: dict, vendors: list) -> list:
    """
    같은 계정 식별자(로컬파트)가 2개 이상 협력사에 걸치거나,
    한 감염 단말이 2개 이상 협력사를 건드린 경우 = 공급망 횡단 신호.
    반환: [{type, key, vendors[], detail}]
    """
    vname = {v["vendor_id"]: v["name"] for v in vendors}
    links = []

    # (a) 계정 재사용: 동일 로컬파트가 여러 협력사에서 유출
    ident_to_vendors = {}
    for vid, rows in leaks_by_v.items():
        for r in rows:
            ident = _identity_of(r)
            if len(ident) >= 3:
                ident_to_vendors.setdefault(ident, set()).add(vid)
    for vid, logs in stealers_by_v.items():
        for log in logs:
            for c in log.get("credentials", []):
                ident = _identity_of(c)
                if len(ident) >= 3:
                    ident_to_vendors.setdefault(ident, set()).add(vid)
    for ident, vids in ident_to_vendors.items():
        if len(vids) >= 2:
            links.append({
                "type": "credential_reuse",
                "key": ident,
                "vendors": sorted(vname.get(v, v) for v in vids),
                "vendor_ids": sorted(vids),
                "detail": f"동일 계정 식별자 '{ident}'가 {len(vids)}개 협력사에서 관측 — 재사용/횡적 이동 가능성",
            })

    # (b) 단말 횡단: 한 감염 단말이 여러 협력사 크리덴셜을 보유
    machine_to_vendors = {}
    for vid, logs in stealers_by_v.items():
        for log in logs:
            mid = log.get("machine_id")
            if mid:
                machine_to_vendors.setdefault(mid, set()).add(vid)
    for mid, vids in machine_to_vendors.items():
        if len(vids) >= 2:
            links.append({
                "type": "shared_machine",
                "key": mid,
                "vendors": sorted(vname.get(v, v) for v in vids),
                "vendor_ids": sorted(vids),
                "detail": f"단일 감염 단말 '{mid}'이 {len(vids)}개 협력사 자격증명 보유 — 공급망 경유 접점",
            })

    return sorted(links, key=lambda x: -len(x["vendors"]))
