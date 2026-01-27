"""
IDS Suite - Security Suite Control Panel
Modular package for Suricata/Snort IDS and ClamAV Antivirus management
"""

__version__ = "2.9.1"
__author__ = "Security Suite"

from ids_suite.core.config import Config
from ids_suite.ui.main_window import SecurityControlPanel

__all__ = ['Config', 'SecurityControlPanel']
