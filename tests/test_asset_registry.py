import pytest

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    UserContext,
    UserRole,
)


@pytest.fixture
def registry() -> AssetIdentityRegistry:
    """Provides a pre-configured AssetIdentityRegistry instance with sample infrastructure."""
    reg = AssetIdentityRegistry()

    # Explicit asset records
    reg.register_asset(
        AssetContext(
            hostname="core-db01.corp",
            ip_address="10.100.4.50",
            criticality=CriticalityLevel.MISSION_CRITICAL,
            business_unit="Core Banking",
            is_crown_jewel=True,
            environment="production",
        )
    )
    reg.register_asset(
        AssetContext(
            hostname="jump-host.corp",
            ip_address="192.168.10.15",
            criticality=CriticalityLevel.HIGH,
            business_unit="SecOps",
            is_crown_jewel=False,
            environment="production",
        )
    )

    # CIDR subnet zones
    reg.register_subnet_zone(
        cidr="10.200.0.0/16",
        criticality=CriticalityLevel.HIGH,
        business_unit="Payment Gateway DMZ",
        is_crown_jewel=True,
    )
    reg.register_subnet_zone(
        cidr="172.16.50.0/24",
        criticality=CriticalityLevel.MEDIUM,
        business_unit="Branch Office VDI",
        is_crown_jewel=False,
    )

    # Identity records
    reg.register_user(
        UserContext(
            username="secops_admin",
            role=UserRole.PRIVILEGED_ADMIN,
            department="Information Security",
            is_vip=True,
            approved_source_subnets=["192.168.10.0/24", "10.50.0.0/24"],
        )
    )
    reg.register_user(
        UserContext(
            username="exec_ciso",
            role=UserRole.EXECUTIVE_VIP,
            department="Executive Office",
            is_vip=True,
            approved_source_subnets=[],
        )
    )
    reg.register_user(
        UserContext(
            username="svc_backup",
            role=UserRole.SERVICE_ACCOUNT,
            department="Infrastructure",
            is_vip=False,
            approved_source_subnets=["10.100.4.0/24"],
        )
    )
    reg.register_user(
        UserContext(
            username="j_doe",
            role=UserRole.STANDARD,
            department="Accounting",
            is_vip=False,
            approved_source_subnets=[],
        )
    )

    return reg


def test_get_asset_by_hostname_exact_and_case_insensitive(registry: AssetIdentityRegistry):
    """Verify resolving assets by hostname handles mixed casing correctly."""
    asset_lower = registry.get_asset("core-db01.corp")
    assert asset_lower.hostname == "core-db01.corp"
    assert asset_lower.criticality == CriticalityLevel.MISSION_CRITICAL
    assert asset_lower.is_crown_jewel is True

    asset_upper = registry.get_asset("CORE-DB01.CORP")
    assert asset_upper.hostname == "core-db01.corp"
    assert asset_upper.ip_address == "10.100.4.50"


def test_get_asset_by_static_ip(registry: AssetIdentityRegistry):
    """Verify resolving assets by exact registered static IP address."""
    asset = registry.get_asset("10.100.4.50")
    assert asset.hostname == "core-db01.corp"
    assert asset.criticality == CriticalityLevel.MISSION_CRITICAL
    assert asset.business_unit == "Core Banking"


def test_get_asset_cidr_subnet_zone_fallback(registry: AssetIdentityRegistry):
    """Verify uncataloged IP addresses resolve into matching CIDR subnet zones."""
    zone_ip = "10.200.45.10"
    asset = registry.get_asset(zone_ip)
    assert asset.criticality == CriticalityLevel.HIGH
    assert asset.business_unit == "Payment Gateway DMZ"
    assert asset.is_crown_jewel is True
    assert asset.ip_address == zone_ip

    branch_ip = "172.16.50.88"
    asset_branch = registry.get_asset(branch_ip)
    assert asset_branch.criticality == CriticalityLevel.MEDIUM
    assert asset_branch.business_unit == "Branch Office VDI"
    assert asset_branch.is_crown_jewel is False


def test_get_asset_uncataloged_fallback(registry: AssetIdentityRegistry):
    """Verify uncataloged hostnames and external IPs safely return low-criticality defaults."""
    unknown_host = registry.get_asset("unknown-desktop-99")
    assert unknown_host.hostname == "unknown-desktop-99"
    assert unknown_host.criticality == CriticalityLevel.LOW
    assert unknown_host.is_crown_jewel is False
    assert unknown_host.ip_address is None

    unknown_ip = registry.get_asset("198.51.100.22")
    assert unknown_ip.hostname == "198.51.100.22"
    assert unknown_ip.ip_address == "198.51.100.22"
    assert unknown_ip.criticality == CriticalityLevel.LOW


def test_is_crown_jewel_evaluations(registry: AssetIdentityRegistry):
    """Verify is_crown_jewel returns accurate flags across assets and zones."""
    assert registry.is_crown_jewel("core-db01.corp") is True
    assert registry.is_crown_jewel("10.100.4.50") is True
    assert registry.is_crown_jewel("10.200.10.1") is True  # Inside payment DMZ
    assert registry.is_crown_jewel("jump-host.corp") is False
    assert registry.is_crown_jewel("random-node") is False


def test_get_user_and_case_insensitivity(registry: AssetIdentityRegistry):
    """Verify user resolution correctly identifies registered users and handles case variance."""
    user = registry.get_user("SECOPS_ADMIN")
    assert user.username == "secops_admin"
    assert user.role == UserRole.PRIVILEGED_ADMIN
    assert user.is_vip is True

    uncataloged = registry.get_user("unknown_contractor")
    assert uncataloged.username == "unknown_contractor"
    assert uncataloged.role == UserRole.STANDARD
    assert uncataloged.is_vip is False


def test_is_vip_or_admin(registry: AssetIdentityRegistry):
    """Verify privilege detection flags admins and VIPs while ignoring standard accounts."""
    assert registry.is_vip_or_admin("secops_admin") is True
    assert registry.is_vip_or_admin("exec_ciso") is True
    assert registry.is_vip_or_admin("svc_backup") is False
    assert registry.is_vip_or_admin("j_doe") is False
    assert registry.is_vip_or_admin("ghost_user") is False


def test_is_approved_source_validation(registry: AssetIdentityRegistry):
    """Verify enforcement of approved administrative source subnets."""
    # secops_admin has subnets: 192.168.10.0/24, 10.50.0.0/24
    assert registry.is_approved_source("secops_admin", "192.168.10.200") is True
    assert registry.is_approved_source("secops_admin", "10.50.0.5") is True
    assert registry.is_approved_source("secops_admin", "203.0.113.4") is False

    # Users without subnet restrictions return True unconditionally
    assert registry.is_approved_source("j_doe", "203.0.113.4") is True
    assert registry.is_approved_source("exec_ciso", "198.51.100.1") is True

    # Invalid IP string handling
    assert registry.is_approved_source("secops_admin", "invalid-ip-string") is False
    