from datetime import date, datetime

import whois

WHOIS_ERROR = {
    "created": None,
    "age_days": None,
    "registrar": None,
    "expires": None,
    "expires_days_left": None,
    "error": "Failed to fetch WHOIS",
}


def _first(value):
    # python-whois sometimes returns a list (e.g. several creation dates from different registries)
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _to_date(value):
    # We only care about the calendar day; datetime must be checked first since it subclasses date
    value = _first(value)
    if isinstance(value, datetime):
        return value.date()
    return value if isinstance(value, date) else None


def get_whois_info(domain: str) -> dict:
    try:
        record = whois.whois(domain)

        created = _to_date(record.creation_date)
        if created is None:
            # Unregistered domains come back with no creation date instead of raising
            return dict(WHOIS_ERROR)

        # Some registries (mostly ccTLDs) don't publish an expiry date; that alone isn't a failure
        expires = _to_date(record.expiration_date)
        registrar = _first(record.registrar)
        today = date.today()

        return {
            "created": created.strftime("%Y-%m-%d"),
            "age_days": (today - created).days,
            "registrar": str(registrar) if registrar else None,
            "expires": expires.strftime("%Y-%m-%d") if expires else None,
            # Negative once the domain has expired
            "expires_days_left": (expires - today).days if expires else None,
        }
    except Exception:
        return dict(WHOIS_ERROR)


if __name__ == "__main__":
    for test_domain in ("google.com", "thisdomaindoesnotexist123456.com"):
        print(test_domain, "->", get_whois_info(test_domain))
