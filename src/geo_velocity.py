import ipaddress
import math
from datetime import datetime
from typing import Optional, Tuple
from pydantic import BaseModel, Field

EARTH_RADIUS_KM = 6371.0


class GeoLocation(BaseModel):
    ip: str
    latitude: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(default=None, ge=-180.0, le=180.0)
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None


def calculate_haversine_distance(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """Computes the great-circle distance in kilometers between two points

    on a sphere using the Haversine formula.
    """
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    # Clip numerical precision drift into [-1.0, 1.0]
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return EARTH_RADIUS_KM * c


def calculate_travel_velocity(
    loc1: GeoLocation,
    t1: datetime,
    loc2: GeoLocation,
    t2: datetime,
) -> Optional[float]:
    """Calculates the travel velocity in km/h between two geolocation points in time.

    Returns float('inf') for instantaneous concurrent logins at different locations.
    Returns None if either coordinate is missing.
    """
    if (
        loc1.latitude is None
        or loc1.longitude is None
        or loc2.latitude is None
        or loc2.longitude is None
    ):
        return None

    distance_km = calculate_haversine_distance(
        loc1.latitude, loc1.longitude, loc2.latitude, loc2.longitude
    )

    delta_seconds = abs((t2 - t1).total_seconds())

    if delta_seconds == 0:
        if distance_km > 0.0:
            return float("inf")
        return 0.0

    hours = delta_seconds / 3600.0
    return distance_km / hours


def is_impossible_travel(
    velocity_kmh: Optional[float], threshold_kmh: float = 800.0
) -> bool:
    """Returns True if travel velocity exceeds the commercial aircraft threshold (default 800 km/h)."""
    if velocity_kmh is None:
        return False
    return velocity_kmh > threshold_kmh


class MockGeoIPDatabase:
    """Lightweight in-memory lookup table for offline testing and IP enrichment."""

    MOCK_RECORDS = {
        "197.237.100.1": GeoLocation(ip="197.237.100.1", latitude=-1.286389, longitude=36.817223, country="KE", city="Nairobi", asn="AS33771"),
        "197.237.200.1": GeoLocation(ip="197.237.200.1", latitude=-4.043477, longitude=39.668206, country="KE", city="Mombasa", asn="AS33771"),
        "81.2.69.142": GeoLocation(ip="81.2.69.142", latitude=51.5074, longitude=-0.1278, country="GB", city="London", asn="AS5413"),
        "198.51.100.20": GeoLocation(ip="198.51.100.20", latitude=40.7128, longitude=-74.0060, country="US", city="New York", asn="AS1111"),
        "185.220.101.5": GeoLocation(ip="185.220.101.5", latitude=50.1109, longitude=8.6821, country="DE", city="Frankfurt", asn="AS24940"),
    }

    @classmethod
    def lookup(cls, ip_str: str) -> GeoLocation:
        """Resolves an IP to a GeoLocation object, defaulting to private if RFC 1918."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                return GeoLocation(ip=ip_str, country="PRIVATE")
        except ValueError:
            return GeoLocation(ip=ip_str, country="INVALID")

        return cls.MOCK_RECORDS.get(
            ip_str,
            GeoLocation(ip=ip_str, country="UNKNOWN")
        )
    