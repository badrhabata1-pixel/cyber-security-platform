import dns.resolver

# Seconds per lookup, so one dead nameserver can't stall the whole /scan request
LOOKUP_TIMEOUT = 5


def _lookup(name: str, rdtype: str) -> list:
    # Every record type goes through here, so each lookup is isolated in its own try/except:
    # NXDOMAIN, NoAnswer, Timeout, NoNameservers, bad names... all just mean "no records"
    try:
        return list(dns.resolver.resolve(name, rdtype, lifetime=LOOKUP_TIMEOUT))
    except Exception:
        return []


def _txt_records(name: str) -> list[str]:
    # Long TXT records are split into 255-byte chunks that must be joined back together
    return [b"".join(r.strings).decode(errors="ignore").strip() for r in _lookup(name, "TXT")]


def get_dns_info(domain: str) -> dict:
    if not domain.strip("."):
        # An empty name would resolve as the DNS root and report the root servers as NS
        return {"a": [], "mx": [], "ns": [], "spf": False, "dmarc": False}

    mx_records = sorted(_lookup(domain, "MX"), key=lambda r: r.preference)

    return {
        "a": [r.address for r in _lookup(domain, "A")],
        # A "null MX" (0 .) means the domain accepts no mail, so it isn't listed as a server
        "mx": [host for r in mx_records if (host := str(r.exchange).rstrip("."))],
        "ns": sorted(str(r.target).rstrip(".") for r in _lookup(domain, "NS")),
        # Per RFC 7208 / 7489 the version tag must open the record, so a TXT that merely
        # mentions it elsewhere doesn't count as protection
        "spf": any(txt.lower().startswith("v=spf1") for txt in _txt_records(domain)),
        "dmarc": any(txt.startswith("v=DMARC1") for txt in _txt_records(f"_dmarc.{domain}")),
    }


if __name__ == "__main__":
    for test_domain in ("google.com", "example.com", "thisdomaindoesnotexist123456.com"):
        print(test_domain, "->", get_dns_info(test_domain))
