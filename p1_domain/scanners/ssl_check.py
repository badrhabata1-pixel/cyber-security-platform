import ipaddress
import socket
import ssl
from datetime import datetime, timezone

import dns.resolver

# Seconds for each TCP connect and TLS handshake, so a filtered port 443 can't stall /scan
TIMEOUT = 5
# The OS resolver (socket.getaddrinfo) has no timeout and was seen stalling 11s+ on Windows,
# so addresses are resolved with dnspython (already used by dns_check) under a hard limit
RESOLVE_TIMEOUT = 4
# A domain can resolve to many IPs; trying them all could multiply the timeout
MAX_ADDRESSES = 2

# OpenSSL verify codes -> plain reasons. The console UI picks its badge from keywords
# in these messages ("expired", "mismatch", "self-signed", "untrusted", ...), so keep them stable.
VERIFY_REASONS = {
    9: "Certificate is not valid yet",
    10: "Certificate has expired",
    18: "Self-signed certificate",
    19: "Self-signed certificate in the chain",
    20: "Untrusted certificate: issuer is not a recognised authority",
    21: "Untrusted certificate: the chain could not be verified",
    23: "Certificate has been revoked",
    62: "Hostname mismatch: certificate was not issued for this domain",
}


class _Abort(Exception):
    """Stops the check early; the message is the reason returned to the caller."""


def _failure(reason: str) -> dict:
    return {"valid": False, "issuer": None, "expires": None, "days_left": None, "error": reason}


def _resolve(domain: str) -> list:
    try:
        return [ipaddress.ip_address(domain)]  # Already an IP literal
    except ValueError:
        pass

    # IPv4 first; IPv6 is only tried when the domain has no IPv4 address at all, because
    # hosts without IPv6 routing would otherwise burn a full timeout per address
    for rdtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, rdtype, lifetime=RESOLVE_TIMEOUT)
            return [ipaddress.ip_address(r.address) for r in answers]
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.LifetimeTimeout:
            raise _Abort("DNS lookup timed out")
        except Exception:
            break
    raise _Abort("Domain does not resolve to any address")


def _public_addresses(domain: str) -> list[str]:
    # Connect only to public IPs we vetted ourselves: this stops the scanner from being used
    # to probe localhost or the internal network (SSRF), and pinning the vetted IP for the
    # connection closes the DNS-rebinding gap between check and use
    public = [ip for ip in _resolve(domain) if ip.is_global]
    if not public:
        raise _Abort("Skipped: domain points to a private or internal network address")
    return [str(ip) for ip in public][:MAX_ADDRESSES]


def _connect(domain: str) -> socket.socket:
    last_error = None
    for ip in _public_addresses(domain):
        try:
            return socket.create_connection((ip, 443), timeout=TIMEOUT)
        except OSError as exc:
            last_error = exc
    raise last_error


def _issuer_name(cert: dict) -> str | None:
    # Issuer is a tuple of RDNs, each a tuple of (key, value) pairs
    fields = {key: value for rdn in cert.get("issuer", ()) for key, value in rdn}
    return fields.get("organizationName") or fields.get("commonName")


def get_ssl_info(domain: str) -> dict:
    if not domain:
        return _failure("No domain provided")

    try:
        # Default context = trusted CA store + hostname check + expiry check, same as a browser
        context = ssl.create_default_context()
        with _connect(domain) as sock, context.wrap_socket(sock, server_hostname=domain) as tls:
            cert = tls.getpeercert()

        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        return {
            "valid": True,
            "issuer": _issuer_name(cert),
            "expires": expires.strftime("%Y-%m-%d"),
            # A certificate that passed verification can't be expired, so this is >= 0
            "days_left": (expires - datetime.now(timezone.utc)).days,
        }
    except ssl.SSLCertVerificationError as exc:
        return _failure(VERIFY_REASONS.get(exc.verify_code, f"Untrusted certificate: {exc.verify_message or exc.reason}"))
    except ssl.SSLError as exc:
        detail = (exc.reason or "").replace("_", " ").lower()
        return _failure(f"TLS handshake failed: {detail}" if detail else "TLS handshake failed")
    except _Abort as exc:
        return _failure(str(exc))
    except TimeoutError:
        return _failure("Connection timed out: port 443 did not respond")
    except ConnectionRefusedError:
        return _failure("No HTTPS service: port 443 is closed")
    except OSError:
        return _failure("Connection failed: the server dropped the connection")
    except Exception:
        return _failure("SSL check failed")


if __name__ == "__main__":
    for test_domain in (
        "google.com",
        "expired.badssl.com",
        "self-signed.badssl.com",
        "wrong.host.badssl.com",
        "localhost",
        "thisdomaindoesnotexist123456.com",
    ):
        print(test_domain, "->", get_ssl_info(test_domain))
