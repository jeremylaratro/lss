"""
Shared pytest fixtures for IDS Suite tests
"""

import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing"""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def mock_eve_event() -> Dict[str, Any]:
    """Mock EVE JSON event from Suricata"""
    return {
        "timestamp": "2026-01-21T12:00:00.000000+0000",
        "flow_id": 123456789,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 45678,
        "dest_ip": "203.0.113.10",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024001,
            "rev": 1,
            "signature": "ET MALWARE Suspicious Connection",
            "category": "Malware Command and Control",
            "severity": 1
        },
        "flow": {
            "pkts_toserver": 5,
            "pkts_toclient": 3,
            "bytes_toserver": 500,
            "bytes_toclient": 1500
        }
    }


@pytest.fixture
def mock_eve_events_list() -> list:
    """List of mock EVE events for batch testing"""
    return [
        {
            "timestamp": "2026-01-21T12:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "src_port": 12345,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "alert": {
                "signature_id": 1001,
                "signature": "DNS Query",
                "category": "Protocol Command Decode",
                "severity": 3
            }
        },
        {
            "timestamp": "2026-01-21T12:01:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "dest_ip": "1.2.3.4",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 2001,
                "signature": "HTTP Suspicious Request",
                "category": "Web Application Attack",
                "severity": 2
            }
        },
        {
            "timestamp": "2026-01-21T12:02:00.000000+0000",
            "event_type": "alert",
            "src_ip": "172.16.0.10",
            "src_port": 9999,
            "dest_ip": "5.6.7.8",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature_id": 3001,
                "signature": "SSH Brute Force Attempt",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1
            }
        }
    ]


@pytest.fixture
def mock_eve_file(temp_dir, mock_eve_events_list):
    """Create a mock eve.json file with test events"""
    eve_file = Path(temp_dir) / "eve.json"
    with open(eve_file, 'w') as f:
        for event in mock_eve_events_list:
            f.write(json.dumps(event) + '\n')
    return str(eve_file)


@pytest.fixture
def mock_threat_intel_result() -> Dict[str, Any]:
    """Mock threat intelligence service result"""
    return {
        "indicator": "203.0.113.10",
        "indicator_type": "ip",
        "service": "virustotal",
        "is_malicious": True,
        "score": 8,
        "details": {
            "positives": 8,
            "total": 10,
            "country": "US",
            "asn": "AS12345"
        },
        "timestamp": datetime.now().isoformat()
    }


@pytest.fixture
def mock_threat_intel_results() -> list:
    """List of mock threat intelligence results"""
    return [
        {
            "indicator": "1.2.3.4",
            "indicator_type": "ip",
            "service": "abuseipdb",
            "is_malicious": True,
            "score": 95,
            "details": {
                "abuse_confidence_score": 95,
                "country_code": "CN",
                "usage_type": "Data Center"
            }
        },
        {
            "indicator": "example.com",
            "indicator_type": "domain",
            "service": "virustotal",
            "is_malicious": False,
            "score": 0,
            "details": {
                "positives": 0,
                "total": 85
            }
        },
        {
            "indicator": "44d88612fea8a8f36de82e1278abb02f",
            "indicator_type": "hash",
            "service": "virustotal",
            "is_malicious": True,
            "score": 42,
            "details": {
                "positives": 42,
                "total": 70,
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            }
        }
    ]


@pytest.fixture
def mock_keyring(monkeypatch):
    """Mock keyring module to avoid system keyring dependencies"""
    mock_keys = {}

    class MockKeyring:
        @staticmethod
        def get_password(service, username):
            return mock_keys.get(f"{service}:{username}")

        @staticmethod
        def set_password(service, username, password):
            mock_keys[f"{service}:{username}"] = password

        @staticmethod
        def delete_password(service, username):
            key = f"{service}:{username}"
            if key in mock_keys:
                del mock_keys[key]

    try:
        import keyring
        monkeypatch.setattr(keyring, 'get_password', MockKeyring.get_password)
        monkeypatch.setattr(keyring, 'set_password', MockKeyring.set_password)
        monkeypatch.setattr(keyring, 'delete_password', MockKeyring.delete_password)
    except ImportError:
        pass

    return MockKeyring


@pytest.fixture
def clean_cache():
    """Fixture to ensure clean cache state for tests"""
    from ids_suite.threat_intel.cache import ThreatIntelCache
    cache = ThreatIntelCache()
    cache.clear()
    yield cache
    cache.clear()


@pytest.fixture
def sample_ips():
    """Sample IP addresses for testing"""
    return {
        "private": [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "127.0.0.1",
            "169.254.1.1"
        ],
        "public": [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.1",
            "198.51.100.1",
            "93.184.216.34"
        ],
        "invalid": [
            "256.1.1.1",
            "1.256.1.1",
            "1.1.256.1",
            "1.1.1.256",
            "not.an.ip.address",
            "",
            "192.168.1",
            "192.168.1.1.1"
        ]
    }


@pytest.fixture
def sample_ipv6():
    """Sample IPv6 addresses for testing"""
    return {
        "private": [
            "::1",
            "fe80::1",
            "fe80::dead:beef",
            "fc00::1",
            "fd00::1234:5678",
            "ff02::1"
        ],
        "public": [
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2001:db8::1"
        ]
    }
