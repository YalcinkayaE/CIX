from __future__ import annotations

import pytest

from src.ingest.siem_formats import parse_cef, parse_leef, parse_syslog


def test_parse_cef_basic():
    line = "CEF:0|Acme|ThreatX|1.0|100|Test Event|5|src=10.0.0.1 dst=10.0.0.2 msg=hello"
    parsed = parse_cef(line)
    assert parsed["cef_version"] == "0"
    assert parsed["device_vendor"] == "Acme"
    assert parsed["device_product"] == "ThreatX"
    assert parsed["signature_id"] == "100"
    assert parsed["severity"] == "5"
    assert parsed["extension"]["src"] == "10.0.0.1"
    assert parsed["extension"]["dst"] == "10.0.0.2"


def test_parse_leef_basic():
    line = "LEEF:2.0|Vendor|Product|1.0|EVT123|\tcat=malware\tsev=5"
    parsed = parse_leef(line)
    assert parsed["leef_version"] == "2.0"
    assert parsed["vendor"] == "Vendor"
    assert parsed["product"] == "Product"
    assert parsed["event_id"] == "EVT123"
    assert parsed["extension"]["cat"] == "malware"
    assert parsed["extension"]["sev"] == "5"


def test_parse_syslog_rfc5424():
    line = "<34>1 2026-02-06T10:00:00Z host app 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event"
    parsed = parse_syslog(line)
    assert parsed["rfc"] == "5424"
    assert parsed["pri"] == 34
    assert parsed["hostname"] == "host"
    assert parsed["appname"] == "app"
    assert parsed["msgid"] == "ID47"
    assert parsed["structured_data"][0]["sd_id"] == "exampleSDID@32473"


def test_parse_syslog_rfc3164():
    line = "<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed"
    parsed = parse_syslog(line)
    assert parsed["rfc"] == "3164"
    assert parsed["pri"] == 34
    assert parsed["hostname"] == "mymachine"
    assert parsed["app"] == "su"
    assert parsed["pid"] == "123"
