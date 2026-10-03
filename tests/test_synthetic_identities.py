"""Synthetic data must not point at real people, companies or hosts."""
import ipaddress
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# Real services may appear only as the site a personal credential was saved for.
ALLOWED_REAL = {"google.com", "facebook.com"}


def text(name):
    with open(os.path.join(ROOT, "data", "synthetic", name), encoding="utf-8") as f:
        return f.read()


def test_every_email_uses_a_reserved_domain():
    for name in ("leaked_credentials.json", "stealer_logs.json"):
        for domain in re.findall(r'"[^"@\s]+@([a-z0-9.-]+)"', text(name)):
            assert domain.endswith(".example") or domain in {"example.com", "example.net", "example.org"} \
                or domain in ALLOWED_REAL, domain


def test_every_ip_is_in_a_documentation_range():
    for name in ("stealer_logs.json",):
        for ip in re.findall(r'"(\d{1,3}(?:\.\d{1,3}){3})"', text(name)):
            assert any(ipaddress.ip_address(ip) in n for n in DOC_NETS), ip


def test_vendor_and_c2_domains_are_reserved():
    vendors = json.loads(text("vendors.json"))
    assert all(d.endswith(".example") for v in vendors for d in v["domains"])
    logs = json.loads(text("stealer_logs.json"))
    for c2 in {l["c2_host"] for l in logs if l.get("c2_host")}:
        assert c2.endswith(".example") or any(ipaddress.ip_address(c2) in n for n in DOC_NETS), c2
