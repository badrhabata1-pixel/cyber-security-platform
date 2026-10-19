import ipaddress
import os
from pathlib import Path
try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # dependencies may not be installed during static inspection
    geoip2 = None


class GeoEnricher:
    def __init__(self):
        raw_path = os.getenv("GEOIP_DB_PATH", "geoip/GeoLite2-City.mmdb")
        self.path = Path(raw_path)
        self.reader = None
        if geoip2 and self.path.exists():
            self.reader = geoip2.database.Reader(str(self.path))

    def lookup(self, ip: str | None) -> tuple[str | None, str | None]:
        country, city, _, _ = self.details(ip)
        return country, city

    def details(self, ip: str | None) -> tuple[str | None, str | None, float | None, float | None]:
        if not ip or not self.reader:
            return None, None, None, None
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None, None, None, None
            result = self.reader.city(ip)
            return result.country.iso_code, result.city.name, result.location.latitude, result.location.longitude
        except (ValueError, geoip2.errors.AddressNotFoundError):
            return None, None, None, None
