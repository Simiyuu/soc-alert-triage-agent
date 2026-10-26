from datetime import datetime, timedelta, timezone
import pytest
from src.geo_velocity import (
    GeoLocation,
    calculate_haversine_distance,
    calculate_travel_velocity,
    is_impossible_travel,
)


def test_haversine_distance_nairobi_to_london():
    """Verify spherical distance between Nairobi (-1.286389, 36.817223)

    and London (51.5074, -0.1278) is ~6,825 km (+/- 25 km).
    """
    nairobi = (-1.286389, 36.817223)
    london = (51.5074, -0.1278)
    
    distance = calculate_haversine_distance(nairobi[0], nairobi[1], london[0], london[1])
    assert 6800.0 <= distance <= 6850.0


def test_haversine_distance_identical_points_is_zero():
    """Verify distance between identical points is exactly 0.0 km."""
    distance = calculate_haversine_distance(-1.286389, 36.817223, -1.286389, 36.817223)
    assert distance == pytest.approx(0.0, abs=1e-4)


def test_calculate_travel_velocity_realistic_flight():
    """Verify travel from Nairobi to Mombasa (~440 km) in 60 minutes yields ~440 km/h."""
    t1 = datetime(2026, 10, 25, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 25, 11, 0, 0, tzinfo=timezone.utc)
    
    loc1 = GeoLocation(ip="197.237.100.1", latitude=-1.286389, longitude=36.817223, country="KE", city="Nairobi")
    loc2 = GeoLocation(ip="197.237.200.1", latitude=-4.043477, longitude=39.668206, country="KE", city="Mombasa")
    
    velocity = calculate_travel_velocity(loc1, t1, loc2, t2)
    assert velocity is not None
    assert 430.0 <= velocity <= 460.0
    assert not is_impossible_travel(velocity, threshold_kmh=800.0)


def test_calculate_travel_velocity_impossible_travel():
    """Verify travel from Nairobi to London (~6,825 km) in 15 minutes yields >27,000 km/h."""
    t1 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(minutes=15)
    
    loc1 = GeoLocation(ip="197.237.100.1", latitude=-1.286389, longitude=36.817223, country="KE", city="Nairobi")
    loc2 = GeoLocation(ip="81.2.69.142", latitude=51.5074, longitude=-0.1278, country="GB", city="London")
    
    velocity = calculate_travel_velocity(loc1, t1, loc2, t2)
    assert velocity is not None
    assert velocity > 25000.0
    assert is_impossible_travel(velocity, threshold_kmh=800.0) is True


def test_calculate_travel_velocity_zero_delta_time_concurrent_logins():
    """Verify simultaneous logins (dt=0) from different cities return infinite velocity without ZeroDivisionError."""
    t = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    
    loc1 = GeoLocation(ip="197.237.100.1", latitude=-1.286389, longitude=36.817223, country="KE")
    loc2 = GeoLocation(ip="81.2.69.142", latitude=51.5074, longitude=-0.1278, country="GB")
    
    velocity = calculate_travel_velocity(loc1, t, loc2, t)
    assert velocity == float("inf")
    assert is_impossible_travel(velocity, threshold_kmh=800.0) is True


def test_calculate_travel_velocity_private_or_missing_location():
    """Verify missing coordinates (e.g. private RFC 1918 IPs) return None velocity safely."""
    t1 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(minutes=10)
    
    loc1 = GeoLocation(ip="10.0.0.1", latitude=None, longitude=None, country="PRIVATE")
    loc2 = GeoLocation(ip="197.237.100.1", latitude=-1.286389, longitude=36.817223, country="KE")
    
    velocity = calculate_travel_velocity(loc1, t1, loc2, t2)
    assert velocity is None
    assert is_impossible_travel(velocity) is False