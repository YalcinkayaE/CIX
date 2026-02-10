from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


CEF_HEADER_RE = re.compile(r"^CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<prod_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(.*)$")
LEEF_HEADER_RE = re.compile(r"^LEEF:(?P<version>\d+(?:\.\d+)?)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<prod_version>[^|]*)\|(?P<event_id>[^|]*)\|(.*)$")

RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<version>\d)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>-|\[[^\]]*\](?:\[[^\]]*\])*)"
    r"(?:\s+(?P<msg>.*))?$"
)

RFC3164_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)


def _parse_kv_pairs(text: str, sep: str = " ") -> Dict[str, str]:
    pairs = {}
    if not text:
        return pairs

    if sep == "\t":
        parts = [p for p in text.split("\t") if p]
        for part in parts:
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            pairs[k.strip()] = v.strip()
        return pairs

    # CEF extension parsing with support for escaped spaces and equals
    key = ""
    value = ""
    in_key = True
    escape = False
    current = ""
    tokens: List[str] = []

    for ch in text:
        if escape:
            current += ch
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == " " and not in_key:
            tokens.append(current)
            current = ""
            in_key = True
            continue
        current += ch
        if in_key and ch == "=":
            in_key = False
    if current:
        tokens.append(current)

    for token in tokens:
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        pairs[k.strip()] = v.strip()
    return pairs


def parse_cef(line: str) -> Dict[str, Any]:
    match = CEF_HEADER_RE.match(line)
    if not match:
        raise ValueError("Invalid CEF header")
    ext_text = match.group(8)
    extension = _parse_kv_pairs(ext_text, sep=" ")
    return {
        "cef_version": match.group("version"),
        "device_vendor": match.group("vendor"),
        "device_product": match.group("product"),
        "device_version": match.group("prod_version"),
        "signature_id": match.group("signature_id"),
        "name": match.group("name"),
        "severity": match.group("severity"),
        "extension": extension,
    }


def parse_leef(line: str) -> Dict[str, Any]:
    match = LEEF_HEADER_RE.match(line)
    if not match:
        raise ValueError("Invalid LEEF header")
    ext_text = match.group(6)
    extension = _parse_kv_pairs(ext_text, sep="\t")
    return {
        "leef_version": match.group("version"),
        "vendor": match.group("vendor"),
        "product": match.group("product"),
        "product_version": match.group("prod_version"),
        "event_id": match.group("event_id"),
        "extension": extension,
    }


def _parse_structured_data(sd: str) -> List[Dict[str, Any]]:
    if sd == "-":
        return []
    blocks = re.findall(r"\[([^\]]+)\]", sd)
    parsed = []
    for block in blocks:
        parts = block.split()
        if not parts:
            continue
        sd_id = parts[0]
        params = {}
        for part in parts[1:]:
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            params[k] = v.strip('"')
        parsed.append({"sd_id": sd_id, "params": params})
    return parsed


def parse_syslog(line: str) -> Dict[str, Any]:
    match = RFC5424_RE.match(line)
    if match:
        sd_raw = match.group("structured_data")
        return {
            "rfc": "5424",
            "pri": int(match.group("pri")),
            "version": int(match.group("version")),
            "timestamp": match.group("timestamp"),
            "hostname": match.group("hostname"),
            "appname": match.group("appname"),
            "procid": match.group("procid"),
            "msgid": match.group("msgid"),
            "structured_data": _parse_structured_data(sd_raw),
            "message": match.group("msg") or "",
        }
    match = RFC3164_RE.match(line)
    if match:
        return {
            "rfc": "3164",
            "pri": int(match.group("pri")),
            "timestamp": match.group("timestamp"),
            "hostname": match.group("hostname"),
            "app": match.group("tag"),
            "pid": match.group("pid"),
            "message": match.group("msg"),
        }
    raise ValueError("Unrecognized syslog format")
