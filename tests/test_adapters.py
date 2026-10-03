"""Adapter contract (was scripts/test_adapters.py): mock data keeps the schema fields."""
from adapters import BaseAdapter, MockAdapter, PartnerAdapter, get_adapter


def test_mock_adapter_follows_the_schema():
    a = MockAdapter()
    vendors, leaks, stealers = a.load_vendors(), a.load_leaks(), a.load_stealers()
    assert vendors and leaks and stealers
    assert all({"vendor_id", "name", "domains"} <= v.keys() for v in vendors)
    assert all({"record_id", "email", "domain", "first_seen"} <= r.keys() for r in leaks)
    assert all({"log_id", "stealer_family", "infection_date", "credentials"} <= s.keys() for s in stealers)


def test_partner_adapter_interface_without_network():
    assert issubclass(PartnerAdapter, BaseAdapter)
    assert hasattr(PartnerAdapter, "check_connection")
    assert isinstance(get_adapter("partner"), PartnerAdapter)
