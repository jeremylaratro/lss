"""
Tab Components for Security Suite Control Panel

This package contains modular tab implementations extracted from the main_window.py
God Object. Each tab is a self-contained component with its own UI and logic.

Base Classes:
    BaseTab: Abstract base class providing common tab functionality

Available Tabs:
    (To be added as tabs are extracted from main_window.py)
    - OverviewTab
    - AlertsTab
    - TrafficTab
    - LocalhostTab
    - DnsTab
    - ClamAVOverviewTab
    - ClamAVQuarantineTab
    - ClamAVScanTab
    - AnalyticsTab
    - SuricataSettingsTab
    - ClamAVSettingsTab
    - ThreatIntelTab
    - GeneralSettingsTab
    - ConnectionsTab
    - LogsTab
    - FirewallTab
    - SecurityAuditTab
"""

from ids_suite.ui.tabs.base_tab import BaseTab
from ids_suite.ui.tabs.quarantine_tab import QuarantineTab
from ids_suite.ui.tabs.traffic_tab import TrafficTab
from ids_suite.ui.tabs.dns_tab import DNSTab
from ids_suite.ui.tabs.alerts_tab import AlertsTab

__all__ = [
    'BaseTab',
    'QuarantineTab',
    'TrafficTab',
    'DNSTab',
    'AlertsTab',
    # Additional tabs will be added here as they are extracted
]
