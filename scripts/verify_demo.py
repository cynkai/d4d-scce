#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SCCE demo verification.

Run after `python3 scripts/generate_synthetic.py && python3 pipeline.py`.
This checks the claims that should be stable during judging:
- KPI lead time matches replay lead time
- total vs matched credential counts are clearly separated
- top vendor / campaign narrative exists
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "data" / "report.json"


def fail(msg: str) -> None:
    raise SystemExit(f"[FAIL] {msg}")


def main() -> None:
    if not REPORT.exists():
        fail("data/report.json 없음 — python3 pipeline.py 먼저 실행")

    r = json.loads(REPORT.read_text(encoding="utf-8"))
    k = r.get("kpis", {})
    rp = r.get("replay", {})
    ranked = r.get("ranked_vendors", [])
    campaigns = r.get("campaigns", [])

    if k.get("early_warning_lead_days") != rp.get("lead_days"):
        fail(f"KPI lead mismatch: kpi={k.get('early_warning_lead_days')} replay={rp.get('lead_days')}")
    if rp.get("lead_days") != 8:
        fail(f"expected 8-day early warning narrative, got {rp.get('lead_days')}")
    if not ranked or ranked[0].get("name") != "태성회로":
        fail("top-ranked crown-jewel vendor should be 태성회로")
    if not campaigns:
        fail("no campaign detected")
    if k.get("total_observed_credentials", 0) < k.get("matched_exposed_credentials", 0):
        fail("total observed credentials cannot be smaller than matched credentials")
    if k.get("matched_exposed_credentials") != k.get("exposed_credentials"):
        fail("legacy exposed_credentials should equal matched_exposed_credentials")
    if "warroom" in r or "code_exposure" in r:
        fail("removed presentation-noise features still present in report.json")
    if r.get("meta", {}).get("demo_flow") != ["개요", "SIEM", "인시던트 대응", "조사", "보고서·탐지룰"]:
        fail("demo_flow should be the final 5-view presentation path")
    if "evaluation" not in r:
        fail("evaluation summary missing")
    top = ranked[0]
    for key in ("evidence_ledger", "response_impact", "attack_path"):
        if key not in top:
            fail(f"top vendor missing {key}")
    if top["response_impact"]["residual_risk"] >= top["response_impact"]["pre_risk"]:
        fail("response impact should reduce residual risk")

    print("[OK] SCCE demo verification passed")
    print(f"     lead_days={rp.get('lead_days')} early_warning={rp.get('early_warning_day')} hero_peak={rp.get('hero_peak_day')}")
    print(f"     credentials matched/total={k.get('matched_exposed_credentials')}/{k.get('total_observed_credentials')}")
    print(f"     top_vendor={ranked[0].get('name')} score={ranked[0].get('risk_score')}")
    print(f"     campaigns={len(campaigns)} primary={campaigns[0].get('campaign_id')}")


if __name__ == "__main__":
    main()
