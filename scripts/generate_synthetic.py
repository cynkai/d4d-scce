#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
D4D T2 #12 - 방산 공급망 자격증명 노출 조기경보
합성 데이터 생성기 v2 (Synthetic Data Generator)

v2 추가:
  - C2 호스트 / 캠페인 태그 → 여러 협력사를 동시 타격한 '조율된 공급망 공격' 탐지 가능
  - 위협 행위자(threat actor) 귀속
  - 유출 소스 provenance 강화

산출:
  1) vendors.json
  2) leaked_credentials.json
  3) stealer_logs.json

설계 원칙:
  - raw 신호만. 점수/상관/귀속은 분석 엔진이 계산.
  - 시드 고정 → 데모 재현 가능.
  - 회사명·도메인·행위자·C2 전부 가공(fictional).
"""

import argparse
import json
import os
import random
from datetime import date, timedelta

TODAY = date(2026, 7, 4)  # D4D Day 2
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic")

# ---------------------------------------------------------------------------
# 방산 협력사 인벤토리 (가공)
# ---------------------------------------------------------------------------
VENDORS = [
    {"name": "한빛정밀항공",   "tier": 1, "domains": ["hanbit-aero.co.kr"],     "criticality": "항공전자(FCS)",   "employees": 820},
    {"name": "대양유도시스템", "tier": 1, "domains": ["daeyang-guidance.com"],  "criticality": "유도무기 시커",   "employees": 610},
    {"name": "세종전술통신",   "tier": 1, "domains": ["sejong-tactcom.co.kr"],  "criticality": "전술데이터링크", "employees": 540},
    {"name": "누리항공기계",   "tier": 1, "domains": ["nuri-aeromech.com"],     "criticality": "기체 구조물",     "employees": 970},
    {"name": "삼익정밀가공",   "tier": 2, "domains": ["samik-precision.co.kr"], "criticality": "구동장치 부품",   "employees": 140},
    {"name": "동방센서텍",     "tier": 2, "domains": ["dongbang-sensor.com"],   "criticality": "EO/IR 센서 모듈", "employees": 95},
    {"name": "태성회로",       "tier": 2, "domains": ["taesung-pcb.co.kr"],     "criticality": "군용 PCB",        "employees": 60},
    {"name": "우진열처리",     "tier": 2, "domains": ["woojin-heat.com"],       "criticality": "특수 열처리",     "employees": 42},
    {"name": "명성정밀",       "tier": 2, "domains": ["myungsung-fine.co.kr"],  "criticality": "커넥터/하네스",   "employees": 78},
    {"name": "가온소재",       "tier": 2, "domains": ["gaon-materials.com"],    "criticality": "복합소재",       "employees": 120},
    {"name": "청우기전",       "tier": 2, "domains": ["chungwoo-elec.co.kr"],   "criticality": "전원공급장치",   "employees": 55},
    {"name": "한결시스템",     "tier": 2, "domains": ["hangyul-sys.com"],       "criticality": "임베디드 SW",     "employees": 33},
    # [관측편향 데모용] 실제로는 어떤 상태일지 알 수 없는 협력사 — 아래 main()에서
    # 이 업체로 귀속되는 유출/스틸러 레코드를 의도적으로 전부 제거해 "NO SIGNAL"을
    # 재현한다. SCCE가 "신호 없음"을 "안전 확인"으로 오독하지 않는다는 것을 보여주기 위함.
    {"name": "성일방산소재",     "tier": 2, "domains": ["seongil-defense.co.kr"], "criticality": "특수합금 원소재", "employees": 48},
]

FIRST_NAMES = ["minjun", "jiwoo", "seoyeon", "hyun", "jae", "eunji", "doyoon",
               "sujin", "kanghee", "yerin", "taeho", "nari", "sangwoo", "hana",
               "junho", "mira", "wonjin", "seunghyun", "bora", "gitae"]
LAST_NAMES = ["kim", "lee", "park", "choi", "jung", "kang", "cho", "yoon",
              "jang", "lim", "han", "oh", "seo", "shin", "kwon"]

LEAK_SOURCES = [
    "combolist:cloud-2025-mix", "combolist:antipublic-2026",
    "breach:vendorportal-2024", "darkweb_forum:breachforums-repost",
    "telegram_channel:leakbase-kr",
]

STEALER_FAMILIES = ["RedLine", "Lumma", "Vidar", "StealC", "Raccoon"]

# 가공 C2 호스트 (캠페인 상관에 사용)
C2_POOL = [
    "45.147.230.11", "185.220.101.44", "193.42.33.8",
    "cdn-update-sync.net", "win-telemetry-cache.com", "gsvc-report.io",
]

# 가공 위협 행위자 (귀속에 사용)
THREAT_ACTORS = ["Shadow Chisel", "Amber Typhoon", "Reticle-9"]

CRED_CATEGORIES_HIGH = ["vpn", "sso", "admin_panel", "cloud_console", "code_repo"]
CRED_CATEGORIES_LOW = ["webmail", "generic", "saas"]

URL_TEMPLATES = {
    "vpn": "https://vpn.{domain}/remote/login",
    "sso": "https://sso.{domain}/adfs/ls",
    "admin_panel": "https://erp.{domain}/admin",
    "cloud_console": "https://console.{domain}/login",
    "code_repo": "https://git.{domain}/users/sign_in",
    "webmail": "https://mail.{domain}/owa",
    "saas": "https://{domain}.slack.com",
    "generic": "https://portal.{domain}/login",
}


def rand_date(rng, start_days_ago, end_days_ago):
    return (TODAY - timedelta(days=rng.randint(end_days_ago, start_days_ago))).isoformat()


def _age_days(iso):
    y, m, d = map(int, iso.split("-"))
    return (TODAY - __import__("datetime").date(y, m, d)).days


HIGH_SET = {"vpn", "sso", "admin_panel", "cloud_console", "code_repo"}


def make_email(rng, domain):
    return f"{rng.choice(FIRST_NAMES)}.{rng.choice(LAST_NAMES)}@{domain}"


def build_vendors():
    return [{
        "vendor_id": f"V{i:03d}", "name": v["name"], "tier": v["tier"],
        "domains": v["domains"], "criticality": v["criticality"],
        "employees": v["employees"],
    } for i, v in enumerate(VENDORS, start=1)]


def build_leaked_credentials(rng, vendors, n=260):
    dv = {d: v["vendor_id"] for v in vendors for d in v["domains"]}
    corp = list(dv.keys())
    noise = ["gmail.com", "naver.com", "daum.net", "outlook.com", "kakao.com"]
    out = []
    for i in range(1, n + 1):
        if rng.random() < 0.70:
            domain = rng.choice(corp); vid = dv[domain]; is_corp = True
        else:
            domain = rng.choice(noise); vid = None; is_corp = False
        out.append({
            "record_id": f"L{i:05d}", "email": make_email(rng, domain),
            "domain": domain, "vendor_id": vid, "is_corporate": is_corp,
            "password_type": rng.choices(["plaintext", "hash"], weights=[0.6, 0.4])[0],
            "source": rng.choice(LEAK_SOURCES), "first_seen": rand_date(rng, 900, 5),
        })

    # 룩얼라이크(사칭) 도메인 주입 — APT가 협력사를 사칭해 등록하는 오타 도메인.
    # 협력사 도메인에 귀속되지 않으므로(=vid None) 매칭 카운트를 늘리지 않고,
    # matcher.detect_lookalikes 가 별도 사칭 신호로 잡아낸다. (branch 1 실증)
    lookalikes = [
        ("taesung-pbc.co.kr", "taesung-pcb.co.kr"),   # pcb→pbc 인접 전치 (crown-jewel 사칭)
        ("sejong-tactcon.co.kr", "sejong-tactcom.co.kr"),  # tactcom→tactcon 치환 사칭
    ]
    for j, (fake, _real) in enumerate(lookalikes, 1):
        out.append({
            "record_id": f"LK{j:05d}", "email": make_email(rng, fake),
            "domain": fake, "vendor_id": None, "is_corporate": False,
            "password_type": "plaintext",
            "source": "darkweb_forum:supplier-phish-kr", "first_seen": rand_date(rng, 40, 3),
        })
    return out


def _machine(rng, family, vid, domain, infection, c2, campaign, high_prob):
    creds, has_high = [], False
    for _ in range(rng.randint(2, 7)):
        if vid and rng.random() < 0.5:
            cat = rng.choice(CRED_CATEGORIES_HIGH) if rng.random() < high_prob else rng.choice(CRED_CATEGORIES_LOW)
            cdomain = domain
        else:
            cat = rng.choice(CRED_CATEGORIES_LOW)
            cdomain = rng.choice(["google.com", "facebook.com", domain])
        if cat in CRED_CATEGORIES_HIGH and cdomain == domain:
            has_high = True
        creds.append({"url": URL_TEMPLATES[cat].format(domain=cdomain),
                      "category": cat,
                      "username": make_email(rng, cdomain) if "@" not in cdomain else cdomain,
                      "password_type": "plaintext"})
    # gt_active: 생성기가 아는 '진짜 활성 침해' 정답 라벨(탐지기와 독립).
    #   회사 자격증명 + HIGH 카테고리 + 활성 창(30일) 이내 감염일 때만 진짜 위협.
    gt = bool(vid and has_high and _age_days(infection) <= 30)
    return {
        "stealer_family": family, "infection_date": infection,
        "machine_id": f"WIN-{rng.randint(10**6, 10**7-1)}",
        "country": rng.choices(["KR", "KR", "KR", "CN", "RU", "VN"], weights=[5, 5, 5, 1, 1, 1])[0],
        "vendor_id": vid, "is_corporate": bool(vid),
        "c2_host": c2, "campaign_id": campaign,
        "active_compromise": bool(vid and has_high), "gt_active": gt, "credentials": creds,
    }


def build_decoys(rng, vendors):
    """
    평가용 함정(decoy) 로그 — 정답은 '활성 침해 아님'(gt_active=False)이지만,
    나이브 탐지기('회사 도메인 감염이면 무조건 활성')는 오탐하도록 설계.
    우리 스코어링 규칙(최근 30일 + HIGH 크리덴셜)이 실제로 오탐을 거르는지 측정한다.
    """
    dv = {d: v["vendor_id"] for v in vendors for d in v["domains"]}
    corp = list(dv.keys())
    decoys = []

    def mk(domain, cats, age, tag):
        vid = dv[domain]
        infection = (TODAY - timedelta(days=age)).isoformat()
        creds = [{"url": URL_TEMPLATES[c].format(domain=domain), "category": c,
                  "username": make_email(rng, domain), "password_type": "plaintext"} for c in cats]
        return {
            "stealer_family": rng.choice(STEALER_FAMILIES), "infection_date": infection,
            "machine_id": f"WIN-DECOY-{tag}", "country": "KR",
            "vendor_id": vid, "is_corporate": True,
            # c2_host=None: 캠페인/리플레이/IOC 로직에서 제외됨(평가 전용 함정).
            "c2_host": None,
            "campaign_id": None, "active_compromise": False, "gt_active": False,
            "credentials": creds,
        }

    # (a) 오래된 감염(활성 창 밖) + HIGH 크리덴셜 — 이미 지난 위협. 나이브는 오탐.
    for age in (34, 41, 58):
        d = rng.choice(corp)
        decoys.append(mk(d, ["vpn", "sso"], age, f"STALE{age}"))
    # (b) 최근 감염이지만 LOW 크리덴셜만 — 내부망 진입성 낮음. 나이브는 오탐.
    for age in (3, 8, 15):
        d = rng.choice(corp)
        decoys.append(mk(d, ["webmail", "saas", "generic"], age, f"LOW{age}"))

    for i, m in enumerate(decoys, start=1):
        m["log_id"] = f"D{i:05d}"
    return decoys


def build_stealer_logs(rng, vendors, n=40):
    dv = {d: v["vendor_id"] for v in vendors for d in v["domains"]}
    corp = list(dv.keys())
    logs = []
    for _ in range(n):
        corporate = rng.random() < 0.55
        if corporate:
            domain = rng.choice(corp); vid = dv[domain]
        else:
            domain = rng.choice(["gmail.com", "naver.com", "outlook.com"]); vid = None
        logs.append(_machine(rng, rng.choice(STEALER_FAMILIES), vid, domain,
                             rand_date(rng, 400, 1), rng.choice(C2_POOL[:3]),
                             None, high_prob=0.18))
    for i, m in enumerate(logs, start=1):
        m["log_id"] = f"S{i:05d}"
    return logs


def inject_campaign_and_hero(rng, vendors, leaked, stealer):
    """
    핵심: 여러 협력사를 동시 타격한 '조율된 공급망 캠페인'을 심는다.
    같은 스틸러(RedLine) + 같은 C2 + 같은 주(week) → 상관 엔진이 캠페인으로 탐지.
    히어로(태성회로)가 캠페인의 정점.
    """
    by_name = {v["name"]: v for v in vendors}
    campaign_id = "CAMP-REDLINE-KR-0714"
    c2 = "cdn-update-sync.net"
    actor = "Shadow Chisel"

    # 캠페인 구성원: 히어로 + 2개 다른 협력사 (공급망 폭 강조: 1차+2차 혼합)
    #  (업체, 감염 며칠전, _, 유출 카테고리, 단말)
    #  캠페인 확산: 동방(-12) → 세종(-9) → [조기경보 성립] → 태성 crown-jewel(-1)
    members = [
        ("태성회로", 1, 5, ["vpn", "sso", "cloud_console", "admin_panel", "code_repo", "webmail"], "WIN-CAD-07"),
        ("세종전술통신", 9, 2, ["vpn", "sso", "webmail"], "WIN-ENG-22"),
        ("동방센서텍", 12, 2, ["sso", "webmail", "generic"], "WIN-QA-05"),
    ]
    inserted = []
    for name, days_ago, _, cats, mid in members:
        v = by_name[name]; hd = v["domains"][0]
        creds = [{"url": URL_TEMPLATES[c].format(domain=hd), "category": c,
                  "username": make_email(rng, hd), "password_type": "plaintext"} for c in cats]
        rec = {
            "log_id": f"S000{len(inserted)}0", "stealer_family": "RedLine",
            "infection_date": (TODAY - timedelta(days=days_ago)).isoformat(),
            "machine_id": mid, "country": "KR", "vendor_id": v["vendor_id"],
            "is_corporate": True, "c2_host": c2, "campaign_id": campaign_id,
            "threat_actor": actor, "active_compromise": True, "gt_active": True,
            "credentials": creds,
        }
        stealer.insert(0, rec); inserted.append(rec)

    # 히어로 업체에 최근 유출 크리덴셜 몇 건 추가 (상관 강화)
    hero = by_name["태성회로"]; hd = hero["domains"][0]
    for k in range(3):
        leaked.insert(0, {
            "record_id": f"L900{k:02d}", "email": make_email(rng, hd), "domain": hd,
            "vendor_id": hero["vendor_id"], "is_corporate": True,
            "password_type": "plaintext", "source": "telegram_channel:leakbase-kr",
            "first_seen": (TODAY - timedelta(days=rng.randint(3, 20))).isoformat(),
        })
    return campaign_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    os.makedirs(OUT_DIR, exist_ok=True)

    vendors = build_vendors()
    leaked = build_leaked_credentials(rng, vendors)
    stealer = build_stealer_logs(rng, vendors)
    stealer.extend(build_decoys(rng, vendors))   # 평가용 함정(정답=비활성)
    campaign = inject_campaign_and_hero(rng, vendors, leaked, stealer)

    # [관측편향 데모용] "성일방산소재"로 귀속된 레코드를 전부 제거 —
    # 관측 채널(다크웹·스틸러)에 아무 흔적도 없는 상태를 강제로 재현한다.
    # (이 회사가 실제로 안전한지는 SCCE가 알 수 없다 — 그게 핵심이다.)
    NO_SIGNAL_VENDOR = "성일방산소재"
    ns_id = next(v["vendor_id"] for v in vendors if v["name"] == NO_SIGNAL_VENDOR)
    leaked = [r for r in leaked if r.get("vendor_id") != ns_id]
    stealer = [s for s in stealer if s.get("vendor_id") != ns_id]

    for fname, data in {"vendors.json": vendors,
                        "leaked_credentials.json": leaked,
                        "stealer_logs.json": stealer}.items():
        with open(os.path.join(OUT_DIR, fname), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  wrote {fname:26s} ({len(data)} records)")
    print(f"\n캠페인 주입: {campaign}  (히어로=태성회로)")
    print(f"기준일(TODAY)={TODAY.isoformat()}, seed={args.seed}")


if __name__ == "__main__":
    main()
