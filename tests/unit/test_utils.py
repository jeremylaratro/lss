"""
Unit tests for ids_suite.core.utils module
"""

import pytest
from ids_suite.core.utils import is_private_ip


class TestIsPrivateIP:
    """Test suite for is_private_ip() function"""

    # RFC1918 Private IP Ranges Tests

    def test_class_a_private_start(self):
        """Test start of Class A private range (10.0.0.0)"""
        assert is_private_ip("10.0.0.0") is True

    def test_class_a_private_end(self):
        """Test end of Class A private range (10.255.255.255)"""
        assert is_private_ip("10.255.255.255") is True

    def test_class_a_private_middle(self):
        """Test middle of Class A private range"""
        assert is_private_ip("10.123.45.67") is True
        assert is_private_ip("10.1.1.1") is True
        assert is_private_ip("10.200.100.50") is True

    def test_class_b_private_start(self):
        """Test start of Class B private range (172.16.0.0)"""
        assert is_private_ip("172.16.0.0") is True

    def test_class_b_private_end(self):
        """Test end of Class B private range (172.31.255.255)"""
        assert is_private_ip("172.31.255.255") is True

    def test_class_b_private_all_ranges(self):
        """Test all Class B private subnets (172.16-31.x.x)"""
        for second_octet in range(16, 32):
            assert is_private_ip(f"172.{second_octet}.0.0") is True
            assert is_private_ip(f"172.{second_octet}.255.255") is True
            assert is_private_ip(f"172.{second_octet}.100.50") is True

    def test_class_b_boundary_below(self):
        """Test just below Class B private range (172.15.x.x)"""
        assert is_private_ip("172.15.0.0") is False
        assert is_private_ip("172.15.255.255") is False

    def test_class_b_boundary_above(self):
        """Test just above Class B private range (172.32.x.x)"""
        assert is_private_ip("172.32.0.0") is False
        assert is_private_ip("172.32.255.255") is False

    def test_class_c_private_start(self):
        """Test start of Class C private range (192.168.0.0)"""
        assert is_private_ip("192.168.0.0") is True

    def test_class_c_private_end(self):
        """Test end of Class C private range (192.168.255.255)"""
        assert is_private_ip("192.168.255.255") is True

    def test_class_c_private_middle(self):
        """Test middle of Class C private range"""
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("192.168.100.200") is True
        assert is_private_ip("192.168.254.254") is True

    def test_class_c_boundary(self):
        """Test boundaries near Class C private range"""
        assert is_private_ip("192.167.1.1") is False
        assert is_private_ip("192.169.1.1") is False

    # Loopback Tests (127.0.0.0/8)

    def test_loopback_standard(self):
        """Test standard loopback address"""
        assert is_private_ip("127.0.0.1") is True

    def test_loopback_range(self):
        """Test entire loopback range (127.0.0.0/8)"""
        assert is_private_ip("127.0.0.0") is True
        assert is_private_ip("127.255.255.255") is True
        assert is_private_ip("127.1.2.3") is True
        assert is_private_ip("127.100.50.25") is True

    # Link-Local Tests (169.254.0.0/16)

    def test_link_local_start(self):
        """Test start of link-local range (APIPA)"""
        assert is_private_ip("169.254.0.0") is True

    def test_link_local_end(self):
        """Test end of link-local range"""
        assert is_private_ip("169.254.255.255") is True

    def test_link_local_middle(self):
        """Test middle of link-local range"""
        assert is_private_ip("169.254.1.1") is True
        assert is_private_ip("169.254.100.50") is True

    def test_link_local_boundary(self):
        """Test boundaries near link-local range"""
        assert is_private_ip("169.253.1.1") is False
        assert is_private_ip("169.255.1.1") is False

    # Multicast Tests (224.0.0.0/4)

    def test_multicast_start(self):
        """Test start of multicast range"""
        assert is_private_ip("224.0.0.0") is True

    def test_multicast_end(self):
        """Test end of multicast range"""
        assert is_private_ip("239.255.255.255") is True

    def test_multicast_range(self):
        """Test various multicast addresses"""
        assert is_private_ip("224.0.0.1") is True
        assert is_private_ip("230.1.2.3") is True
        assert is_private_ip("239.0.0.0") is True

    # Reserved/Invalid Tests

    def test_zero_network(self):
        """Test 0.0.0.0/8 (invalid/current network)"""
        assert is_private_ip("0.0.0.0") is True
        assert is_private_ip("0.1.2.3") is True
        assert is_private_ip("0.255.255.255") is True

    def test_reserved_240_block(self):
        """Test 240.0.0.0/4 (reserved)"""
        assert is_private_ip("240.0.0.0") is True
        assert is_private_ip("255.255.255.255") is True
        assert is_private_ip("250.1.2.3") is True

    # Public IP Tests

    def test_public_ips(self):
        """Test known public IP addresses"""
        assert is_private_ip("8.8.8.8") is False  # Google DNS
        assert is_private_ip("1.1.1.1") is False  # Cloudflare DNS
        assert is_private_ip("93.184.216.34") is False  # example.com
        assert is_private_ip("151.101.1.140") is False
        assert is_private_ip("216.58.214.206") is False

    def test_documentation_ips(self):
        """Test RFC 5737 documentation IPs (should be public for testing purposes)"""
        # These are reserved for documentation but function treats them as public
        # since they're not in the private/reserved ranges it specifically checks
        assert is_private_ip("192.0.2.1") is False  # TEST-NET-1
        assert is_private_ip("198.51.100.1") is False  # TEST-NET-2
        assert is_private_ip("203.0.113.1") is False  # TEST-NET-3

    # IPv6 Tests

    def test_ipv6_loopback(self):
        """Test IPv6 loopback address"""
        assert is_private_ip("::1") is True

    def test_ipv6_link_local(self):
        """Test IPv6 link-local addresses (fe80::/10)"""
        assert is_private_ip("fe80::1") is True
        assert is_private_ip("fe80::dead:beef") is True
        assert is_private_ip("fe80:0000:0000:0000:0000:0000:0000:0001") is True

    def test_ipv6_unique_local(self):
        """Test IPv6 unique local addresses (fc00::/7)"""
        assert is_private_ip("fc00::1") is True
        assert is_private_ip("fd00::1234:5678") is True
        assert is_private_ip("fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") is True
        assert is_private_ip("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") is True

    def test_ipv6_multicast(self):
        """Test IPv6 multicast addresses (ff00::/8)"""
        assert is_private_ip("ff02::1") is True
        assert is_private_ip("ff05::1:3") is True
        assert is_private_ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") is True

    def test_ipv6_public(self):
        """Test IPv6 public addresses"""
        assert is_private_ip("2001:4860:4860::8888") is False  # Google DNS
        assert is_private_ip("2606:4700:4700::1111") is False  # Cloudflare DNS
        assert is_private_ip("2001:db8::1") is False  # Documentation range

    # Edge Cases and Invalid Input Tests

    def test_empty_string(self):
        """Test empty string"""
        assert is_private_ip("") is True

    def test_none_value(self):
        """Test None value"""
        assert is_private_ip(None) is True

    def test_non_string_input(self):
        """Test non-string inputs"""
        assert is_private_ip(123) is True
        assert is_private_ip([]) is True
        assert is_private_ip({}) is True

    def test_invalid_format(self):
        """Test invalid IP format"""
        assert is_private_ip("not.an.ip") is True
        assert is_private_ip("192.168.1") is True
        assert is_private_ip("192.168.1.1.1") is True
        assert is_private_ip("192.168.1.256") is True
        assert is_private_ip("999.999.999.999") is True

    def test_whitespace_handling(self):
        """Test IP addresses with whitespace"""
        assert is_private_ip("  10.0.0.1  ") is True
        assert is_private_ip("\t192.168.1.1\n") is True
        assert is_private_ip("  8.8.8.8  ") is False

    def test_negative_octets(self):
        """Test negative values in octets"""
        assert is_private_ip("-1.0.0.1") is True
        assert is_private_ip("192.-168.1.1") is True

    def test_non_numeric_octets(self):
        """Test non-numeric octets"""
        assert is_private_ip("192.168.a.1") is True
        assert is_private_ip("x.y.z.w") is True

    def test_special_characters(self):
        """Test IPs with special characters (treated as invalid)"""
        # The function correctly treats these as invalid format
        # which returns True to avoid threat intel lookups
        assert is_private_ip("192.168.1.1/24") is True
        assert is_private_ip("192.168.1.1:8080") is False  # Colon triggers IPv6 check which returns False for this format

    # Comprehensive Range Tests

    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "10.50.100.200", "10.255.255.254",
        "172.16.0.1", "172.20.30.40", "172.31.255.254",
        "192.168.0.1", "192.168.100.100", "192.168.255.254",
        "127.0.0.1", "127.1.2.3", "127.255.255.254",
        "169.254.0.1", "169.254.100.100", "169.254.255.254",
    ])
    def test_all_private_ranges_parametrized(self, ip):
        """Parametrized test for all private IP ranges"""
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "1.0.0.1", "8.8.8.8", "9.9.9.9", "11.0.0.1",
        "172.15.255.255", "172.32.0.0", "173.0.0.1",
        "192.0.0.1", "192.167.1.1", "192.169.1.1", "193.0.0.1",
        "151.101.1.140", "216.58.214.206", "93.184.216.34",
    ])
    def test_all_public_ranges_parametrized(self, ip):
        """Parametrized test for public IP ranges"""
        assert is_private_ip(ip) is False
