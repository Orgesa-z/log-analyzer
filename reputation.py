import ipaddress
import os

import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"
_cache = {}


def check(ip):
    if ip in _cache:
        return _cache[ip]

    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None

    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None

    try:
        r = requests.get(
            API_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        r.raise_for_status()
        d = r.json()["data"]
    except Exception:
        return None

    result = {
        "score": d["abuseConfidenceScore"],
        "country": d.get("countryCode"),
        "reports": d.get("totalReports"),
    }
    _cache[ip] = result
    return result