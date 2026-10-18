import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from dotenv import load_dotenv

    # p1_domain/.env; variables already set in the real environment take precedence
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass  # Without python-dotenv the key can still come from the real environment

VT_URL = "https://www.virustotal.com/api/v3/domains/{}"
TIMEOUT = 5
# The free VirusTotal plan allows 4 lookups per minute, so repeat scans of the same domain
# are answered from memory for a while instead of burning that quota
CACHE_SECONDS = 600
_cache: dict[str, tuple[float, dict]] = {}

# The console UI recognises the "Not found" prefix to show "no reputation data"
# instead of "check unavailable", so keep it stable
NOT_FOUND = "Not found: VirusTotal has no record of this domain"
NOT_ANALYSED = "Not found: VirusTotal has not analysed this domain yet"
HTTP_REASONS = {
    400: "VirusTotal could not process this domain name",
    401: "VirusTotal rejected the API key (check VIRUSTOTAL_API_KEY)",
    403: "VirusTotal denied access for this API key",
    404: NOT_FOUND,
    429: "Rate limit reached: the free VirusTotal plan allows 4 lookups per minute",
}


def _fallback(reason: str) -> dict:
    return {"virustotal": 0, "safebrowsing": "clean", "flagged_by": [], "error": reason}


def _copy(result: dict) -> dict:
    # Cached results are shared, so hand out a fresh flagged_by list every time
    return {**result, "flagged_by": list(result.get("flagged_by", []))}


def _query(domain: str, api_key: str) -> dict | None:
    request = urllib.request.Request(
        VT_URL.format(urllib.parse.quote(domain, safe="")),
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        attributes = json.load(response)["data"]["attributes"]

    results = attributes.get("last_analysis_results") or {}
    if not results:
        return None  # Known to VirusTotal but never analysed: "0 detections" would wrongly read as clean

    # Google Safe Browsing is one of the engines VirusTotal runs, so its verdict comes with the report
    google = results.get("Google Safe Browsing", {})
    return {
        "virustotal": int(attributes.get("last_analysis_stats", {}).get("malicious", 0)),
        "safebrowsing": "unsafe" if google.get("category") in ("malicious", "suspicious") else "clean",
        # Same "malicious" category the count uses, so the names always line up with the number
        "flagged_by": sorted(
            (entry.get("engine_name") or name for name, entry in results.items() if entry.get("category") == "malicious"),
            key=str.lower,
        ),
    }


def get_blacklist_info(domain: str) -> dict:
    if not domain:
        return _fallback("No domain provided")

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _fallback("VirusTotal API key is not configured (VIRUSTOTAL_API_KEY in .env)")

    cached = _cache.get(domain)
    if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
        return _copy(cached[1])

    # Error messages never include the API key or the raw exception text
    try:
        result = _query(domain, api_key)
    except urllib.error.HTTPError as exc:
        result = _fallback(HTTP_REASONS.get(exc.code, f"VirusTotal returned HTTP {exc.code}"))
        if exc.code != 404:
            return result  # Only "no record" is a stable answer worth caching
    except TimeoutError:
        return _fallback(f"VirusTotal did not respond within {TIMEOUT} seconds")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            return _fallback(f"VirusTotal did not respond within {TIMEOUT} seconds")
        return _fallback("Could not reach VirusTotal")
    except (ValueError, KeyError, TypeError):
        return _fallback("Unexpected response from VirusTotal")
    except Exception:
        return _fallback("VirusTotal lookup failed")

    if result is None:
        return _fallback(NOT_ANALYSED)  # Not cached: an analysis may land any minute
    if len(_cache) > 1000:
        _cache.clear()
    _cache[domain] = (time.monotonic(), result)
    return _copy(result)


if __name__ == "__main__":
    for test_domain in ("google.com", "wicar.org"):
        print(test_domain, "->", get_blacklist_info(test_domain))
