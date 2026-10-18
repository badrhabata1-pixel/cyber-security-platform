import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

MAX_URL_LENGTH = 75
MAX_HOST_DOTS = 3
MAX_HYPHENS = 2  # 3 or more is flagged

# Each finding is "<title>: <specifics>". The console UI keys its explanations off these titles,
# so keep them stable.
TITLE_IP = "IP address instead of a domain name"
TITLE_LONG = "Unusually long URL"
TITLE_SUBDOMAINS = "Too many subdomains"
TITLE_AT = "Hidden destination behind an @ symbol"
TITLE_HYPHENS = "Hyphen-stuffed domain name"
TITLE_KEYWORDS = "Sensitive keywords in a suspicious context"
TITLE_TLD = "High-risk domain ending"
TITLE_HOMOGRAPH = "Look-alike characters from another alphabet"

ACTION_WORDS = {"login", "verify", "account", "banking", "secure", "update", "wallet", "signin", "confirm"}
# Brand names are suspicious anywhere in a host that isn't the brand's own domain
BRANDS = {"paypal"}

# TLDs consistently over-represented in phishing and abuse reports: the former free Freenom
# endings plus cheap gTLDs favoured by automated campaigns, and the file-name look-alikes .zip / .mov
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "icu", "cyou", "buzz", "sbs", "cfd", "rest", "zip", "mov",
}

# Browsers also accept IPv4 written as one number or in hex/octal (http://3232235777/ = 192.168.1.1)
NUMERIC_HOST = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$")
# Second-level labels that form a public suffix together with a country code (co.uk, com.au, ...)
SECOND_LEVEL_SUFFIXES = {"co", "com", "net", "org", "gov", "edu", "ac"}


def _empty_details() -> dict:
    return {
        "ip_host": False,
        "long_url": False,
        "many_subdomains": False,
        "at_symbol": False,
        "many_hyphens": False,
        "sensitive_keywords": False,
        "high_risk_tld": False,
        "homograph": False,
    }


def _tokens(text: str) -> set[str]:
    return {token for token in re.split(r"[^a-z]+", text.lower()) if token}


def _is_ip(host: str) -> bool:
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
            return True
        except ValueError:
            return False
    return bool(NUMERIC_HOST.match(host))


def _registrable_label(labels: list[str]) -> str:
    # The name the owner actually registered: "evil" in login.paypal.com.evil.co.uk.
    # Approximated without the full Public Suffix List.
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_SUFFIXES:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else ""


def _keyword_hits(labels: list[str], path_and_query: str, deceptive_host: bool) -> list[str]:
    # Words like "login" are everywhere on legitimate sites, so they only count in contexts
    # phishers rely on, not anywhere they happen to appear
    registrable = _registrable_label(labels)
    hits = set()

    # 1. A brand name on a domain that isn't the brand's own (paypal.com.evil.xyz, paypal-help.com)
    hits |= {brand for brand in BRANDS if brand in ".".join(labels) and registrable != brand}
    # 2. Action words baked into the registered name itself (secure-login.com, wallet-verify.net)
    hits |= ACTION_WORDS & _tokens(registrable)
    # 3. Several action words stacked in the hostname (login.verify.example.com); a single
    #    "login." subdomain is common on real sites and doesn't count
    host_words = ACTION_WORDS & _tokens(".".join(labels[:-1]))
    if len(host_words) >= 2:
        hits |= host_words
    # 4. Bait words in the path only matter when the domain itself is already risky (high-risk TLD)
    if deceptive_host:
        hits |= (ACTION_WORDS | BRANDS) & _tokens(path_and_query)
    return sorted(hits)


def _lookalike_scripts(host: str) -> list[str]:
    # Cyrillic and Greek letters can be pixel-identical to Latin ones (Cyrillic "а" vs Latin "a").
    # Mixing them with Latin anywhere in the host, including a .com ending, is the homograph
    # trick; a fully Cyrillic name under .рф or an Arabic domain is not flagged.
    labels = []
    for label in host.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except (UnicodeError, ValueError):
            labels.append(label)

    scripts = {unicodedata.name(ch, "UNKNOWN").split()[0] for ch in "".join(labels) if ch.isalpha()}
    lookalikes = scripts & {"CYRILLIC", "GREEK"}
    return sorted(lookalikes) if lookalikes and "LATIN" in scripts else []


def analyze_heuristics(url_or_domain: str) -> dict:
    details = _empty_details()
    try:
        raw = url_or_domain.strip()
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = (parsed.hostname or "").rstrip(".")
        labels = [label for label in host.split(".") if label]
        tld = labels[-1] if len(labels) >= 2 else ""
        findings = []

        details["ip_host"] = _is_ip(host)
        if details["ip_host"]:
            findings.append(f"{TITLE_IP}: {host}")

        details["long_url"] = len(raw) > MAX_URL_LENGTH
        if details["long_url"]:
            findings.append(f"{TITLE_LONG}: {len(raw)} characters (limit {MAX_URL_LENGTH})")

        dots = host.count(".")
        details["many_subdomains"] = not details["ip_host"] and dots > MAX_HOST_DOTS
        if details["many_subdomains"]:
            findings.append(f"{TITLE_SUBDOMAINS}: {dots} dots in {host}")

        # Only an @ in the address part is the trick; an e-mail address in the query string is not
        details["at_symbol"] = "@" in parsed.netloc and bool(host)
        if details["at_symbol"]:
            shown = parsed.netloc.rsplit("@", 1)[0]
            findings.append(f"{TITLE_AT}: looks like {shown} but opens {host}")

        # Punycode prefixes (xn--) contain hyphens of their own, so they don't count
        hyphens = re.sub(r"(^|\.)xn--", r"\1", host).count("-")
        details["many_hyphens"] = hyphens > MAX_HYPHENS
        if details["many_hyphens"]:
            findings.append(f"{TITLE_HYPHENS}: {hyphens} hyphens in {host}")

        details["high_risk_tld"] = not details["ip_host"] and tld in HIGH_RISK_TLDS

        path_and_query = f"{parsed.path}?{parsed.query}"
        if details["ip_host"]:
            # A raw IP has no domain name to inspect, so a bait word in the path is the context
            keywords = sorted((ACTION_WORDS | BRANDS) & _tokens(path_and_query))
        else:
            keywords = _keyword_hits(labels, path_and_query, details["high_risk_tld"])
        details["sensitive_keywords"] = bool(keywords)
        if keywords:
            findings.append(f"{TITLE_KEYWORDS}: {', '.join(keywords)}")

        if details["high_risk_tld"]:
            findings.append(f"{TITLE_TLD}: .{tld}")

        scripts = _lookalike_scripts(host)
        details["homograph"] = bool(scripts)
        if scripts:
            findings.append(f"{TITLE_HOMOGRAPH}: mixes Latin with {' and '.join(s.title() for s in scripts)} letters")

        return {
            "suspicious_count": len(findings),
            "findings": findings,
            "is_suspicious": len(findings) >= 2,
            "details": details,
        }
    except Exception:
        return {
            "suspicious_count": 0,
            "findings": [],
            "is_suspicious": False,
            "details": _empty_details(),
            "error": "Could not parse the URL",
        }


if __name__ == "__main__":
    for test_input in (
        "google.com",
        "http://192.168.1.1/login",
        "https://paypal.com@evil.tk/login",
        "secure-login-paypal-verify.com",
        "http://secure.login.paypal.com.account-verify.xyz/update",
    ):
        print(test_input, "->", analyze_heuristics(test_input))
