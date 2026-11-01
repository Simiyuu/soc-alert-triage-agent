import ipaddress
from typing import Dict, List, Optional, Tuple, Union

from src.models import (
    AssetContext,
    CriticalityLevel,
    UserContext,
    UserRole,
)


class AssetIdentityRegistry:
    """Central registry resolving network endpoints and identities against organizational context."""

    def __init__(self) -> None:
        self._assets_by_hostname: Dict[str, AssetContext] = {}
        self._assets_by_ip: Dict[str, AssetContext] = {}
        self._subnet_zones: List[
            Tuple[
                Union[ipaddress.IPv4Network, ipaddress.IPv6Network],
                CriticalityLevel,
                str,
                bool,
            ]
        ] = []
        self._users_by_name: Dict[str, UserContext] = {}

    def register_asset(self, asset: AssetContext) -> None:
        """Registers a specific host record by hostname and optional IP address."""
        key_host = asset.hostname.strip().lower()
        self._assets_by_hostname[key_host] = asset
        if asset.ip_address:
            self._assets_by_ip[asset.ip_address.strip()] = asset

    def register_subnet_zone(
        self,
        cidr: str,
        criticality: CriticalityLevel = CriticalityLevel.LOW,
        business_unit: str = "Infrastructure",
        is_crown_jewel: bool = False,
    ) -> None:
        """Registers a CIDR subnet zone to classify uncataloged hosts in specific network blocks."""
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        self._subnet_zones.append((network, criticality, business_unit, is_crown_jewel))

    def register_user(self, user: UserContext) -> None:
        """Registers an identity profile with organizational role and approved subnets."""
        key_user = user.username.strip().lower()
        self._users_by_name[key_user] = user

    def get_asset(self, identifier: str) -> AssetContext:
        """Resolves an asset by hostname, IP address, or enclosing CIDR subnet zone.

        Falls back to a default low-criticality asset context if uncataloged.
        """
        clean_id = identifier.strip()
        clean_id_lower = clean_id.lower()

        # 1. Exact match on hostname
        if clean_id_lower in self._assets_by_hostname:
            return self._assets_by_hostname[clean_id_lower]

        # 2. Exact match on static IP
        if clean_id in self._assets_by_ip:
            return self._assets_by_ip[clean_id]

        # 3. CIDR subnet zone matching if identifier parses as an IP address
        try:
            target_ip = ipaddress.ip_address(clean_id)
            for network, criticality, business_unit, is_crown_jewel in self._subnet_zones:
                if target_ip in network:
                    return AssetContext(
                        hostname=f"zone-{network.network_address}_{network.prefixlen}",
                        ip_address=clean_id,
                        criticality=criticality,
                        business_unit=business_unit,
                        is_crown_jewel=is_crown_jewel,
                        environment="production",
                    )
        except ValueError:
            pass

        # 4. Fallback default context
        return AssetContext(
            hostname=clean_id,
            ip_address=clean_id if self._is_valid_ip(clean_id) else None,
            criticality=CriticalityLevel.LOW,
            business_unit="Uncataloged",
            is_crown_jewel=False,
            environment="unknown",
        )

    def get_user(self, username: str) -> UserContext:
        """Resolves user profile by username, falling back to a standard user context."""
        clean_name = username.strip().lower()
        if clean_name in self._users_by_name:
            return self._users_by_name[clean_name]

        return UserContext(
            username=username.strip(),
            role=UserRole.STANDARD,
            department="Uncataloged",
            is_vip=False,
            approved_source_subnets=[],
        )

    def is_crown_jewel(self, identifier: str) -> bool:
        """Returns True if the identifier maps to an asset flagged as a crown jewel."""
        return self.get_asset(identifier).is_crown_jewel

    def is_vip_or_admin(self, username: str) -> bool:
        """Returns True if the user holds administrative or executive VIP privileges."""
        user = self.get_user(username)
        return user.is_vip or user.role in (
            UserRole.PRIVILEGED_ADMIN,
            UserRole.EXECUTIVE_VIP,
        )

    def is_approved_source(self, username: str, source_ip: str) -> bool:
        """Verifies if the source IP belongs to the user's approved administrative subnets.

        Returns True if the user has no subnet constraints defined.
        """
        user = self.get_user(username)
        if not user.approved_source_subnets:
            return True

        try:
            ip_obj = ipaddress.ip_address(source_ip.strip())
            for subnet_str in user.approved_source_subnets:
                subnet_obj = ipaddress.ip_network(subnet_str.strip(), strict=False)
                if ip_obj in subnet_obj:
                    return True
        except ValueError:
            return False

        return False

    @staticmethod
    def _is_valid_ip(addr: str) -> bool:
        """Helper checking if a string conforms to IPv4 or IPv6 syntax."""
        try:
            ipaddress.ip_address(addr.strip())
            return True
        except ValueError:
            return False
        