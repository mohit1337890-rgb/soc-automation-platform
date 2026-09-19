"""Real GeoIP resolution via IPinfo (https://ipinfo.io), used to make
impossible-travel detection work against REAL Windows remote logons (EID
4624, logon type 3/10) even though live cloud/AD sign-in-log ingestion
isn't wired up yet - see detectors/impossible_travel.py.

Results are cached in-memory per process run since the same source IP
commonly recurs across many logon events in one scan.
"""
import requests

_CACHE: dict[str, dict | None] = {}

_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3",
                      "192.168.", "127.", "169.254.")


def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return ip in ("::1", "localhost") or ip.startswith(_PRIVATE_PREFIXES)


def resolve_ip(ip: str, api_key: str) -> dict | None:
    """Returns {"city", "country", "lat", "lon"} or None if it can't be
    resolved (no key, private IP, API error) - callers should skip the IP
    gracefully rather than treat None as an error.
    """
    if not api_key or is_private_ip(ip):
        return None
    if ip in _CACHE:
        return _CACHE[ip]

    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", params={"token": api_key}, timeout=8)
        if resp.status_code != 200:
            _CACHE[ip] = None
            return None
        data = resp.json()
        loc = data.get("loc")  # "lat,lon"
        if not loc or "," not in loc:
            _CACHE[ip] = None
            return None
        lat_str, lon_str = loc.split(",", 1)
        result = {
            "city": data.get("city", "Unknown"),
            "country": data.get("country", "Unknown"),
            "lat": float(lat_str),
            "lon": float(lon_str),
        }
        _CACHE[ip] = result
        return result
    except (requests.RequestException, ValueError, KeyError):
        _CACHE[ip] = None
        return None
