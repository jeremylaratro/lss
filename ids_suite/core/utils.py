"""
Utility functions for the Security Suite
"""


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/LAN (should not be sent to threat intel APIs).

    Returns True for:
    - 10.0.0.0/8 (Class A private)
    - 172.16.0.0/12 (Class B private)
    - 192.168.0.0/16 (Class C private)
    - 127.0.0.0/8 (Loopback)
    - 169.254.0.0/16 (Link-local)
    - 224.0.0.0/4 (Multicast)
    - 0.0.0.0/8 (Invalid/this network)
    - ::1, fe80::/10, fc00::/7 (IPv6 private/link-local)
    """
    if not ip or not isinstance(ip, str):
        return True  # Invalid, don't look up

    ip = ip.strip()

    # Handle IPv6
    if ':' in ip:
        ip_lower = ip.lower()
        # IPv6 loopback
        if ip_lower == '::1':
            return True
        # IPv6 link-local (fe80::/10)
        if ip_lower.startswith('fe80:'):
            return True
        # IPv6 unique local (fc00::/7 - includes fd00::/8)
        if ip_lower.startswith('fc') or ip_lower.startswith('fd'):
            return True
        # IPv6 multicast (ff00::/8)
        if ip_lower.startswith('ff'):
            return True
        return False

    # IPv4 validation and checks
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return True  # Invalid format

        octets = [int(p) for p in parts]
        if not all(0 <= o <= 255 for o in octets):
            return True  # Invalid range

        first, second = octets[0], octets[1]

        # 0.0.0.0/8 - Invalid/current network
        if first == 0:
            return True

        # 10.0.0.0/8 - Class A private
        if first == 10:
            return True

        # 127.0.0.0/8 - Loopback
        if first == 127:
            return True

        # 169.254.0.0/16 - Link-local (APIPA)
        if first == 169 and second == 254:
            return True

        # 172.16.0.0/12 - Class B private (172.16.0.0 - 172.31.255.255)
        if first == 172 and 16 <= second <= 31:
            return True

        # 192.168.0.0/16 - Class C private
        if first == 192 and second == 168:
            return True

        # 224.0.0.0/4 - Multicast (224.0.0.0 - 239.255.255.255)
        if 224 <= first <= 239:
            return True

        # 240.0.0.0/4 - Reserved (240.0.0.0 - 255.255.255.255)
        if first >= 240:
            return True

        return False

    except (ValueError, AttributeError):
        return True  # Invalid, don't look up
