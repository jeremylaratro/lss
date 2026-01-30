"""
Security Suite Control Panel - Main Window
Comprehensive monitoring and control interface for Suricata IDS + ClamAV Antivirus
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import json
import threading
import os
import csv
import io
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Import from our modular packages
from ids_suite.core.constants import Colors
from ids_suite.core.dependencies import (
    CTK_AVAILABLE,
    MATPLOTLIB_AVAILABLE,
    GEOIP_AVAILABLE,
    KEYRING_AVAILABLE,
    REQUESTS_AVAILABLE,
    get_ctk,
    get_keyring,
    get_matplotlib_components,
    get_geoip,
)
from ids_suite.core.utils import is_private_ip

from ids_suite.engines import SuricataEngine, SnortEngine
from ids_suite.models import EVEFileReader
from ids_suite.threat_intel import (
    VirusTotalClient,
    OTXClient,
    ThreatFoxClient,
    AbuseIPDBClient,
    IPLookupTracker,
)
from ids_suite.services.privilege_helper import run_privileged_batch
from ids_suite.ui.widget_factory import WidgetFactory
from ids_suite.core.validators import (
    validate_port, validate_sid, validate_service_name,
    validate_systemctl_action, validate_ufw_action,
    validate_protocol, validate_file_path
)

# Get optional dependencies
ctk = get_ctk()
keyring = get_keyring()
FigureCanvasTkAgg, Figure, mdates = get_matplotlib_components()


def get_clamav_user():
    """Detect the ClamAV user/group based on the system.

    Fedora uses 'clamupdate:clamupdate', Debian/Ubuntu uses 'clamav:clamav'.
    Returns tuple of (user, group) - falls back to root:root if neither exists.
    """
    import pwd
    import grp

    # Try Fedora first (clamupdate)
    try:
        pwd.getpwnam('clamupdate')
        grp.getgrnam('clamupdate')
        return ('clamupdate', 'clamupdate')
    except KeyError:
        pass

    # Try Debian/Ubuntu (clamav)
    try:
        pwd.getpwnam('clamav')
        grp.getgrnam('clamav')
        return ('clamav', 'clamav')
    except KeyError:
        pass

    # Fallback to root
    return ('root', 'root')


class SecurityControlPanel:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Suite Control Panel v2.5")
        self.root.geometry("1000x750")
        self.root.configure(bg='#2c3746')

        # Colors matching your polybar theme
        self.colors = {
            'bg': '#2c3746',
            'bg_alt': '#343f53',
            'fg': '#ffffff',
            'blue': '#176ef1',
            'red': '#fd3762',
            'teal': '#2aacaa',
            'yellow': '#f7c067',
            'orange': '#f77067',
            'purple': '#cb75f7',
            'cyan': '#5cc6d1',
            'gray': '#9cacad',
            'green': '#2aacaa',
        }

        # Initialize widget factory for modern UI
        self.widgets = WidgetFactory(self.colors)

        # Initialize IDS engines
        self.suricata_engine = SuricataEngine()
        self.snort_engine = SnortEngine()
        self.active_engines = []
        if self.suricata_engine.is_installed():
            self.active_engines.append(self.suricata_engine)
        if self.snort_engine.is_installed():
            self.active_engines.append(self.snort_engine)

        # Load all API keys at once (single keyring unlock)
        self._api_key_cache = self._load_all_api_keys()

        # Initialize threat intelligence clients using cached keys
        self.vt_client = VirusTotalClient(self._api_key_cache.get('virustotal'))
        self.otx_client = OTXClient(self._api_key_cache.get('otx'))
        self.threatfox_client = ThreatFoxClient()  # No API key required
        self.abuseipdb_client = AbuseIPDBClient(self._api_key_cache.get('abuseipdb'))
        self.ip_tracker = IPLookupTracker()  # Track IPs looked up within 3-day window

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()

        self.auto_refresh = tk.BooleanVar(value=True)
        self.refresh_interval = 5000  # 5 seconds

        # Engine filter for alerts (suricata, snort, or both)
        self.engine_filter = tk.StringVar(value="all")

        # Alert filter sets (hide specific signatures, IPs, categories)
        self.hidden_signatures = set()
        self.hidden_src_ips = set()
        self.hidden_dest_ips = set()
        self.hidden_categories = set()

        # Scan process reference for cancel functionality
        self.scan_process = None
        self.scan_cancelled = False

        # Search functionality
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.on_search_changed)

        # Alert data storage for Treeview
        self.alerts_data = []

        # Time range tracking for alerts (to persist across auto-refresh)
        self.selected_time_range = 'live'  # 'live', '24h', '7d', '30d', 'custom'

        # EVE file reader for incremental reading with rotation detection
        self.eve_reader = EVEFileReader()
        self.eve_event_buffer = []  # ALL parsed events within retention window (raw JSON dicts)
        self.eve_initial_load_done = False
        self.eve_buffer_last_update = None  # Track when buffer was last updated

        # Data retention settings (in minutes)
        self.data_retention_minutes = 120  # Default 120 minutes

        # Cached data with timestamps for each tab
        self.activity_cache = []  # Overview tab recent activity
        self.traffic_cache = {'protocols': {}, 'http_hosts': {}, 'tls_hosts': {}, 'last_update': None}
        self.localhost_cache = {'port_activity': {}, 'events': [], 'last_update': None}
        self.dns_cache = {'queries': {}, 'query_types': {}, 'last_update': None}

        # CENTRALIZED service status cache - ONE source of truth for all tabs
        # Updated by _refresh_service_status_cache(), read by all UI components
        self._service_status_cache = {
            'suricata': {'active': False, 'enabled': False},
            'clamav_daemon': {'active': False, 'enabled': False},
            'clamav_freshclam': {'active': False, 'enabled': False},
            'clamav_clamonacc': {'active': False, 'enabled': False},
            'last_update': None
        }

        # Load saved settings before creating widgets
        self.load_settings()

        self.create_widgets()
        self.bind_keyboard_shortcuts()
        self.refresh_status()

        # Update filter count indicator (filters loaded before widgets)
        self._update_filter_count()

        # Perform initial data load for all tabs (in background thread)
        self.root.after(100, self._initial_data_load)

        self.start_auto_refresh()

    def _load_all_api_keys(self) -> dict:
        """Load all API keys from keyring in a single session.

        This minimizes keyring unlock prompts by fetching all keys at once.
        """
        keys = {}
        if KEYRING_AVAILABLE:
            try:
                # Fetch all keys in rapid succession while keyring is unlocked
                for service in ['virustotal', 'otx', 'abuseipdb']:
                    key = keyring.get_password("security-suite", service)
                    if key:
                        keys[service] = key
            except Exception as e:
                print(f"Warning: Could not load API keys from keyring: {e}")
        return keys

    def _get_api_key(self, service: str) -> str:
        """Get API key from cache or keyring"""
        # First check cache
        if hasattr(self, '_api_key_cache') and service in self._api_key_cache:
            return self._api_key_cache[service]

        # Fallback to direct keyring access
        if KEYRING_AVAILABLE:
            try:
                return keyring.get_password("security-suite", service)
            except:
                pass
        return None

    def _set_api_key(self, service: str, key: str):
        """Store API key in keyring and update cache"""
        if KEYRING_AVAILABLE:
            try:
                keyring.set_password("security-suite", service, key)
                # Update cache
                if hasattr(self, '_api_key_cache'):
                    if key:
                        self._api_key_cache[service] = key
                    elif service in self._api_key_cache:
                        del self._api_key_cache[service]
                return True
            except:
                pass
        return False

    def configure_styles(self):
        # Full dark mode styling for all ttk widgets
        bg = self.colors['bg']
        bg_alt = self.colors['bg_alt']
        fg = self.colors['fg']
        blue = self.colors['blue']
        cyan = self.colors['cyan']
        gray = self.colors['gray']

        # Base frame and label styles
        self.style.configure('TFrame', background=bg)
        self.style.configure('TLabel', background=bg, foreground=fg, font=('Hack Nerd Font', 10))
        self.style.configure('Title.TLabel', font=('Hack Nerd Font', 14, 'bold'), foreground=cyan)
        self.style.configure('Status.TLabel', font=('Hack Nerd Font', 12))

        # LabelFrame (used for settings groups)
        self.style.configure('TLabelframe', background=bg, foreground=fg)
        self.style.configure('TLabelframe.Label', background=bg, foreground=cyan, font=('Hack Nerd Font', 10, 'bold'))

        # Button styles
        self.style.configure('TButton', font=('Hack Nerd Font', 10), background=bg_alt, foreground=fg)
        self.style.map('TButton',
            background=[('active', blue), ('pressed', blue)],
            foreground=[('active', fg), ('pressed', fg)])
        self.style.configure('Start.TButton', foreground=self.colors['green'])
        self.style.configure('Stop.TButton', foreground=self.colors['red'])

        # Notebook (tabs)
        self.style.configure('TNotebook', background=bg, borderwidth=0)
        self.style.configure('TNotebook.Tab', font=('Hack Nerd Font', 9), padding=[6, 3],
                            background=bg_alt, foreground=fg)
        self.style.map('TNotebook.Tab',
            background=[('selected', bg), ('active', blue)],
            foreground=[('selected', cyan), ('active', fg)])

        # Checkbutton and Radiobutton
        self.style.configure('TCheckbutton', background=bg, foreground=fg, font=('Hack Nerd Font', 10))
        self.style.map('TCheckbutton', background=[('active', bg)])
        self.style.configure('TRadiobutton', background=bg, foreground=fg, font=('Hack Nerd Font', 10))
        self.style.map('TRadiobutton', background=[('active', bg)])

        # Entry fields
        self.style.configure('TEntry', fieldbackground=bg_alt, foreground=fg, insertcolor=fg)
        self.style.map('TEntry', fieldbackground=[('focus', bg_alt)])

        # Combobox
        self.style.configure('TCombobox', fieldbackground=bg_alt, background=bg_alt,
                            foreground=fg, arrowcolor=fg)
        self.style.map('TCombobox',
            fieldbackground=[('readonly', bg_alt)],
            selectbackground=[('readonly', blue)],
            selectforeground=[('readonly', fg)])
        # Fix combobox dropdown colors (requires option_add)
        self.root.option_add('*TCombobox*Listbox.background', bg_alt)
        self.root.option_add('*TCombobox*Listbox.foreground', fg)
        self.root.option_add('*TCombobox*Listbox.selectBackground', blue)
        self.root.option_add('*TCombobox*Listbox.selectForeground', fg)

        # Spinbox
        self.style.configure('TSpinbox', fieldbackground=bg_alt, background=bg_alt,
                            foreground=fg, arrowcolor=fg)

        # Scrollbar
        self.style.configure('TScrollbar', background=bg_alt, troughcolor=bg,
                            arrowcolor=fg, bordercolor=bg)
        self.style.map('TScrollbar', background=[('active', gray)])

        # Scale (slider)
        self.style.configure('TScale', background=bg, troughcolor=bg_alt)

        # Separator
        self.style.configure('TSeparator', background=gray)

        # Treeview styles for alerts
        self.style.configure('Alerts.Treeview', background=bg_alt,
                            foreground=fg, fieldbackground=bg_alt,
                            font=('Hack Nerd Font', 9))
        self.style.configure('Alerts.Treeview.Heading', font=('Hack Nerd Font', 9, 'bold'),
                            background=bg, foreground=cyan)
        self.style.map('Alerts.Treeview', background=[('selected', blue)])

        # Default Treeview style
        self.style.configure('Treeview', background=bg_alt, foreground=fg,
                            fieldbackground=bg_alt, font=('Hack Nerd Font', 9))
        self.style.configure('Treeview.Heading', font=('Hack Nerd Font', 9, 'bold'),
                            background=bg, foreground=cyan)
        self.style.map('Treeview', background=[('selected', blue)])

        # Progress bar style
        self.style.configure('Custom.Horizontal.TProgressbar',
                            background=blue, troughcolor=bg_alt)
        self.style.configure('TProgressbar', background=blue, troughcolor=bg_alt)

        # PanedWindow
        self.style.configure('TPanedwindow', background=bg)

        # Menu colors (tk, not ttk)
        self.root.option_add('*Menu.background', bg_alt)
        self.root.option_add('*Menu.foreground', fg)
        self.root.option_add('*Menu.activeBackground', blue)
        self.root.option_add('*Menu.activeForeground', fg)
        self.root.option_add('*Menu.selectColor', cyan)

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header with status
        self.create_header(main_frame)

        # Search bar
        self.create_search_bar(main_frame)

        # Progress bar (hidden by default)
        self.create_progress_bar(main_frame)

        # Single notebook with all tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # Create all monitoring tabs
        self.create_overview_tab()
        self.create_alerts_tab()
        self.create_traffic_tab()
        self.create_localhost_tab()
        self.create_dns_tab()
        self.create_clamav_overview_tab()
        self.create_clamav_quarantine_tab()
        self.create_clamav_scan_tab()
        self.create_analytics_tab()

        # Create config tabs (using shorter names to fit)
        self.create_suricata_settings_tab()
        self.create_clamav_settings_tab()
        self.create_threat_intel_tab()
        self.create_general_settings_tab()

        # Create new security tabs
        self.create_connections_tab()
        self.create_logs_tab()
        self.create_firewall_tab()
        self.create_security_audit_tab()

    def create_header(self, parent):
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Title
        title_label = ttk.Label(header_frame, text="󰒃  Security Suite Control Panel", style='Title.TLabel')
        title_label.pack(side=tk.LEFT)

        # Status indicators frame (right side)
        status_container = ttk.Frame(header_frame)
        status_container.pack(side=tk.RIGHT)

        # Refresh button
        self.refresh_btn = self.widgets.create_button(status_container, text="󰑐", command=self.refresh_all, width=3)
        self.refresh_btn.pack(side=tk.RIGHT, padx=(10, 0))
        self.create_tooltip(self.refresh_btn, "Refresh All (F5)")

        # ClamAV Status
        clamav_frame = tk.Frame(status_container, bg=self.colors['bg_alt'], padx=8, pady=4)
        clamav_frame.pack(side=tk.RIGHT, padx=5)

        tk.Label(clamav_frame, text="󰕑 AV", font=('Hack Nerd Font', 9),
                 bg=self.colors['bg_alt'], fg=self.colors['gray']).pack(side=tk.LEFT)
        self.clamav_status_icon = tk.Label(clamav_frame, text="●", font=('Hack Nerd Font', 12),
                                            bg=self.colors['bg_alt'], fg=self.colors['gray'])
        self.clamav_status_icon.pack(side=tk.LEFT, padx=(5, 0))
        self.create_tooltip(clamav_frame, "ClamAV Antivirus Status")

        self.clamav_start_btn = self.widgets.create_button(status_container, text="󰐊", command=self.start_clamav, width=3)
        self.clamav_start_btn.pack(side=tk.RIGHT, padx=1)
        self.create_tooltip(self.clamav_start_btn, "Start ClamAV")
        self.clamav_stop_btn = self.widgets.create_button(status_container, text="󰓛", command=self.stop_clamav, width=3)
        self.clamav_stop_btn.pack(side=tk.RIGHT, padx=1)
        self.create_tooltip(self.clamav_stop_btn, "Stop ClamAV")

        # Separator
        ttk.Separator(status_container, orient='vertical').pack(side=tk.RIGHT, fill='y', padx=10)

        # Suricata Status
        suricata_frame = tk.Frame(status_container, bg=self.colors['bg_alt'], padx=8, pady=4)
        suricata_frame.pack(side=tk.RIGHT, padx=5)

        tk.Label(suricata_frame, text="󰒃 IDS", font=('Hack Nerd Font', 9),
                 bg=self.colors['bg_alt'], fg=self.colors['gray']).pack(side=tk.LEFT)
        self.status_icon = tk.Label(suricata_frame, text="●", font=('Hack Nerd Font', 12),
                                     bg=self.colors['bg_alt'], fg=self.colors['gray'])
        self.status_icon.pack(side=tk.LEFT, padx=(5, 0))
        self.create_tooltip(suricata_frame, "Suricata IDS Status")

        self.start_btn = self.widgets.create_button(status_container, text="󰐊", command=self.start_ids, width=3)
        self.start_btn.pack(side=tk.RIGHT, padx=1)
        self.create_tooltip(self.start_btn, "Start Suricata IDS")
        self.stop_btn = self.widgets.create_button(status_container, text="󰓛", command=self.stop_ids, width=3)
        self.stop_btn.pack(side=tk.RIGHT, padx=1)
        self.create_tooltip(self.stop_btn, "Stop Suricata IDS")

    def create_search_bar(self, parent):
        """Create global search bar"""
        search_frame = ttk.Frame(parent)
        search_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(search_frame, text="󰍉", font=('Hack Nerd Font', 12)).pack(side=tk.LEFT, padx=(0, 5))
        self.search_entry = self.widgets.create_entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.create_tooltip(self.search_entry, "Search current tab (Ctrl+F)")

        clear_btn = self.widgets.create_button(search_frame, text="󰅖", width=3, command=self.clear_search)
        clear_btn.pack(side=tk.LEFT, padx=(5, 0))
        self.create_tooltip(clear_btn, "Clear search (Esc)")

    def create_progress_bar(self, parent):
        """Create progress bar for long operations"""
        self.progress_frame = ttk.Frame(parent)
        # Don't pack yet - shown only during operations

        self.progress_label = ttk.Label(self.progress_frame, text="Working...")
        self.progress_label.pack(side=tk.LEFT, padx=(0, 10))

        self.progress_bar = ttk.Progressbar(self.progress_frame, style='Custom.Horizontal.TProgressbar',
                                            length=300, mode='indeterminate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def create_tooltip(self, widget, text):
        """Create tooltip for a widget"""
        def show_tooltip(event):
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")

            label = tk.Label(tooltip, text=text, background=self.colors['bg_alt'],
                           foreground=self.colors['fg'], relief='solid', borderwidth=1,
                           font=('Hack Nerd Font', 9), padx=5, pady=2)
            label.pack()

            widget.tooltip = tooltip

            def hide_tooltip(e):
                if hasattr(widget, 'tooltip'):
                    widget.tooltip.destroy()
                    del widget.tooltip

            widget.bind('<Leave>', hide_tooltip)
            tooltip.bind('<Leave>', hide_tooltip)

        widget.bind('<Enter>', show_tooltip)

    def bind_keyboard_shortcuts(self):
        """Bind keyboard shortcuts"""
        # Tab switching: Ctrl+1-9
        for i in range(1, 10):
            self.root.bind(f'<Control-Key-{i}>', lambda e, idx=i-1: self.switch_tab(idx))

        # Refresh: F5
        self.root.bind('<F5>', lambda e: self.refresh_all())

        # Search focus: Ctrl+F
        self.root.bind('<Control-f>', lambda e: self.focus_search())

        # Clear search: Escape
        self.root.bind('<Escape>', lambda e: self.clear_search())

    def switch_tab(self, index):
        """Switch to tab by index"""
        try:
            self.notebook.select(index)
        except tk.TclError:
            pass  # Invalid tab index

    def focus_search(self):
        """Focus the search entry"""
        self.search_entry.focus_set()
        self.search_entry.select_range(0, tk.END)

    def clear_search(self):
        """Clear search and reset focus"""
        self.search_var.set('')
        self.root.focus_set()

    def on_search_changed(self, *args):
        """Handle search text changes"""
        search_text = self.search_var.get().lower()
        current_tab = self.notebook.index(self.notebook.select())

        # Apply search to current tab
        if current_tab == 1:  # Alerts tab
            self.filter_alerts_treeview(search_text)

    def show_progress(self, message="Working..."):
        """Show progress bar with message"""
        self.progress_label.configure(text=message)
        self.progress_frame.pack(fill=tk.X, pady=(0, 5))
        self.progress_bar.start(10)

    def hide_progress(self):
        """Hide progress bar"""
        self.progress_bar.stop()
        self.progress_frame.pack_forget()

    def create_overview_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰋼 Overview")

        # Stats grid
        stats_frame = ttk.Frame(tab)
        stats_frame.pack(fill=tk.X, pady=10)

        self.stat_widgets = {}
        stats = [
            ('alerts', '󰀦 Alerts', self.colors['red']),
            ('http', '󰖟 HTTP', self.colors['blue']),
            ('dns', '󰇖 DNS', self.colors['teal']),
            ('tls', '󰌆 TLS', self.colors['purple']),
            ('ssh', '󰣀 SSH', self.colors['yellow']),
            ('localhost', '󰒋 Localhost', self.colors['cyan']),
        ]

        for i, (key, label, color) in enumerate(stats):
            frame = tk.Frame(stats_frame, bg=self.colors['bg_alt'], padx=15, pady=10)
            frame.grid(row=0, column=i, padx=5, pady=5, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)

            tk.Label(frame, text=label, font=('Hack Nerd Font', 10),
                    bg=self.colors['bg_alt'], fg=color).pack()
            count_label = tk.Label(frame, text="0", font=('Hack Nerd Font', 18, 'bold'),
                                   bg=self.colors['bg_alt'], fg=self.colors['fg'])
            count_label.pack()
            self.stat_widgets[key] = count_label

        # Recent activity
        activity_label = ttk.Label(tab, text="Recent Activity", style='Title.TLabel')
        activity_label.pack(anchor=tk.W, pady=(20, 5))

        self.activity_text = self.widgets.create_textbox(tab, height=15,
                                                        bg=self.colors['bg_alt'],
                                                        fg=self.colors['fg'],
                                                        font=('Hack Nerd Font', 9),
                                                        insertbackground=self.colors['fg'])
        self.activity_text.pack(fill=tk.BOTH, expand=True)

    def create_alerts_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰀦 Alerts")

        # Time range presets frame (new)
        time_frame = ttk.Frame(tab)
        time_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(time_frame, text="󰅐 Time Range:", font=('Hack Nerd Font', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 10))

        # Preset buttons
        self.widgets.create_button(time_frame, text="Live", width=6,
                    command=lambda: self._set_time_range('live')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="24h", width=6,
                    command=lambda: self._set_time_range('24h')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="7 days", width=6,
                    command=lambda: self._set_time_range('7d')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="30 days", width=7,
                    command=lambda: self._set_time_range('30d')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="Custom", width=7,
                    command=self._show_custom_date_dialog).pack(side=tk.LEFT, padx=2)

        # Status label showing current time range
        self.time_range_status = ttk.Label(time_frame, text=f"󰋚 Live (last {self.data_retention_minutes} min)", foreground=self.colors['green'])
        self.time_range_status.pack(side=tk.LEFT, padx=(15, 0))

        # Historical mode indicator
        self.historical_mode = False
        self.historical_alerts = []

        # Filter frame
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, pady=(0, 10))

        # Engine filter (Suricata/Snort/Both)
        self.widgets.create_label(filter_frame, text="Engine:").pack(side=tk.LEFT, padx=(0, 5))
        engine_values = ["All"]
        if self.suricata_engine.is_installed():
            engine_values.append("Suricata")
        if self.snort_engine.is_installed():
            engine_values.append("Snort")
        engine_combo = ttk.Combobox(filter_frame, textvariable=self.engine_filter,
                                     values=engine_values, width=10, state='readonly')
        engine_combo.pack(side=tk.LEFT, padx=(0, 15))
        engine_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_alerts())

        self.widgets.create_label(filter_frame, text="Severity:").pack(side=tk.LEFT, padx=(0, 5))
        self.severity_var = tk.StringVar(value="all")
        severity_combo = ttk.Combobox(filter_frame, textvariable=self.severity_var,
                                       values=["all", "1 - High", "2 - Medium", "3 - Low"], width=15)
        severity_combo.pack(side=tk.LEFT, padx=(0, 15))
        severity_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_alerts())

        # Date range filter (hidden by default, shown in custom mode)
        self.date_filter_frame = ttk.Frame(filter_frame)
        self.widgets.create_label(self.date_filter_frame, text="From:").pack(side=tk.LEFT, padx=(10, 5))
        self.date_from_var = tk.StringVar(value="")
        date_from_entry = self.widgets.create_entry(self.date_filter_frame, textvariable=self.date_from_var, width=12)
        date_from_entry.pack(side=tk.LEFT)
        self.create_tooltip(date_from_entry, "YYYY-MM-DD format")

        self.widgets.create_label(self.date_filter_frame, text="To:").pack(side=tk.LEFT, padx=(10, 5))
        self.date_to_var = tk.StringVar(value="")
        date_to_entry = self.widgets.create_entry(self.date_filter_frame, textvariable=self.date_to_var, width=12)
        date_to_entry.pack(side=tk.LEFT)
        self.create_tooltip(date_to_entry, "YYYY-MM-DD format")

        # Bind date entry fields to refresh on change (Enter key or focus out)
        date_from_entry.bind('<Return>', lambda e: self._refresh_historical_alerts())
        date_from_entry.bind('<FocusOut>', lambda e: self._refresh_historical_alerts())
        date_to_entry.bind('<Return>', lambda e: self._refresh_historical_alerts())
        date_to_entry.bind('<FocusOut>', lambda e: self._refresh_historical_alerts())
        # Date filter frame is packed when needed

        # Export button
        export_btn = self.widgets.create_button(filter_frame, text="󰈔 Export", command=self.export_alerts)
        export_btn.pack(side=tk.RIGHT, padx=5)
        self.create_tooltip(export_btn, "Export alerts to CSV")

        # Manage filters button
        self.filter_btn = self.widgets.create_button(filter_frame, text="󰈲 Filters", command=self._show_filter_manager)
        self.filter_btn.pack(side=tk.RIGHT, padx=5)
        self.create_tooltip(self.filter_btn, "Manage hidden signatures/IPs")

        # Filter count indicator
        self.filter_count_label = ttk.Label(filter_frame, text="", foreground=self.colors['orange'])
        self.filter_count_label.pack(side=tk.RIGHT, padx=5)

        self.widgets.create_button(filter_frame, text="󰑐 Refresh", command=self.refresh_alerts).pack(side=tk.RIGHT)

        # Alerts Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        self.alerts_tree_frame = tree_frame  # Store for resize binding

        # Create Treeview with columns (sev shows numeric severity, intel shows threat status)
        columns = ('timestamp', 'sev', 'signature', 'source', 'destination', 'category', 'intel')
        self.alerts_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                        style='Alerts.Treeview')

        # Configure columns - optimized widths with severity column
        self.alerts_tree.heading('timestamp', text='Time', command=lambda: self.sort_alerts('timestamp'))
        self.alerts_tree.heading('sev', text='Sev', command=lambda: self.sort_alerts('sev'))
        self.alerts_tree.heading('signature', text='Signature', command=lambda: self.sort_alerts('signature'))
        self.alerts_tree.heading('source', text='Source', command=lambda: self.sort_alerts('source'))
        self.alerts_tree.heading('destination', text='Destination', command=lambda: self.sort_alerts('destination'))
        self.alerts_tree.heading('category', text='Cat', command=lambda: self.sort_alerts('category'))
        self.alerts_tree.heading('intel', text='Intel', command=lambda: self.sort_alerts('intel'))

        # Column widths: compact timestamp, small sev, generous signature, minimal category
        self.alerts_tree.column('timestamp', width=70, minwidth=60)
        self.alerts_tree.column('sev', width=35, minwidth=30, anchor='center')
        self.alerts_tree.column('signature', width=280, minwidth=150)
        self.alerts_tree.column('source', width=130, minwidth=90)
        self.alerts_tree.column('destination', width=130, minwidth=90)
        self.alerts_tree.column('category', width=50, minwidth=40)
        self.alerts_tree.column('intel', width=90, minwidth=70, anchor='center')

        # Add scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        # Grid layout for treeview and scrollbars
        self.alerts_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Configure tags for severity colors
        self.alerts_tree.tag_configure('high', foreground=self.colors['red'])
        self.alerts_tree.tag_configure('medium', foreground=self.colors['orange'])
        self.alerts_tree.tag_configure('low', foreground=self.colors['yellow'])

        # Bind events
        self.alerts_tree.bind('<Double-1>', self.show_alert_details)
        self.alerts_tree.bind('<Button-3>', self.show_alert_context_menu)

        # Bind resize event for auto-adjusting columns
        tree_frame.bind('<Configure>', self._on_alerts_tree_resize)

        # Sort state
        self.alerts_sort_column = 'timestamp'
        self.alerts_sort_reverse = True

    def create_traffic_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰖟 Traffic")

        # Header with controls
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="󰖟 Network Traffic Analysis", style='Title.TLabel').pack(side=tk.LEFT)

        # Protocol filter
        self.widgets.create_label(header_frame, text="Protocol:").pack(side=tk.LEFT, padx=(20, 5))
        self.traffic_proto_filter = tk.StringVar(value="all")
        proto_combo = ttk.Combobox(header_frame, textvariable=self.traffic_proto_filter,
                                   values=["all", "HTTP", "TLS", "SSH", "SMB", "RDP"],
                                   width=8, state='readonly')
        proto_combo.pack(side=tk.LEFT, padx=(0, 10))
        proto_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_traffic())

        # Ungroup toggle (grouped by destination is default)
        self.traffic_ungrouped = tk.BooleanVar(value=False)
        self.traffic_ungroup_btn = self.widgets.create_button(
            header_frame, text="󰘷 Ungroup",
            command=self._toggle_traffic_grouping
        )
        self.traffic_ungroup_btn.pack(side=tk.LEFT, padx=(10, 5))

        self.widgets.create_button(header_frame, text="󰑐 Refresh",
                                   command=self.refresh_traffic).pack(side=tk.RIGHT, padx=5)

        # Stats summary
        self.traffic_stats_label = ttk.Label(header_frame, text="", foreground=self.colors['cyan'])
        self.traffic_stats_label.pack(side=tk.RIGHT, padx=10)

        # Traffic Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('timestamp', 'protocol', 'source', 'destination', 'host', 'details')
        self.traffic_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                         style='Alerts.Treeview')

        self.traffic_tree.heading('timestamp', text='Timestamp', command=lambda: self.sort_traffic('timestamp'))
        self.traffic_tree.heading('protocol', text='Proto', command=lambda: self.sort_traffic('protocol'))
        self.traffic_tree.heading('source', text='Source', command=lambda: self.sort_traffic('source'))
        self.traffic_tree.heading('destination', text='Destination', command=lambda: self.sort_traffic('destination'))
        self.traffic_tree.heading('host', text='Host/SNI', command=lambda: self.sort_traffic('host'))
        self.traffic_tree.heading('details', text='Details', command=lambda: self.sort_traffic('details'))

        # Sort state for traffic
        self.traffic_sort_column = 'timestamp'
        self.traffic_sort_reverse = True

        self.traffic_tree.column('timestamp', width=140, minwidth=100)
        self.traffic_tree.column('protocol', width=60, minwidth=50, anchor='center')
        self.traffic_tree.column('source', width=130, minwidth=100)
        self.traffic_tree.column('destination', width=130, minwidth=100)
        self.traffic_tree.column('host', width=200, minwidth=150)
        self.traffic_tree.column('details', width=250, minwidth=150)

        # Scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.traffic_tree.xview)
        self.traffic_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.traffic_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Color tags for protocols
        self.traffic_tree.tag_configure('http', foreground=self.colors['green'])
        self.traffic_tree.tag_configure('tls', foreground=self.colors['cyan'])
        self.traffic_tree.tag_configure('ssh', foreground=self.colors['yellow'])
        self.traffic_tree.tag_configure('smb', foreground=self.colors['orange'])

        # Bindings
        self.traffic_tree.bind('<Button-3>', self._show_traffic_context_menu)
        self.traffic_tree.bind('<Double-1>', self._show_traffic_details)

    def create_localhost_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰒋 Local")

        ttk.Label(tab, text="Development Environment Activity", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 10))

        self.localhost_text = self.widgets.create_textbox(tab,
                                                         bg=self.colors['bg_alt'],
                                                         fg=self.colors['fg'],
                                                         font=('Hack Nerd Font', 9),
                                                         insertbackground=self.colors['fg'])
        self.localhost_text.pack(fill=tk.BOTH, expand=True)

    def create_dns_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰇖 DNS")

        # Header with controls
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="󰇖 DNS Query Analysis", style='Title.TLabel').pack(side=tk.LEFT)

        # Filter controls
        self.widgets.create_label(header_frame, text="Type:").pack(side=tk.LEFT, padx=(20, 5))
        self.dns_type_filter = tk.StringVar(value="all")
        dns_type_combo = ttk.Combobox(header_frame, textvariable=self.dns_type_filter,
                                      values=["all", "A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SOA"],
                                      width=8, state='readonly')
        dns_type_combo.pack(side=tk.LEFT, padx=(0, 10))
        dns_type_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_dns())

        # Ungroup toggle (grouped by domain is default)
        self.dns_ungrouped = tk.BooleanVar(value=False)
        self.dns_ungroup_btn = self.widgets.create_button(
            header_frame, text="󰘷 Ungroup",
            command=self._toggle_dns_grouping
        )
        self.dns_ungroup_btn.pack(side=tk.LEFT, padx=(10, 5))

        self.widgets.create_button(header_frame, text="󰑐 Refresh",
                                   command=self.refresh_dns).pack(side=tk.RIGHT, padx=5)

        # Stats summary bar
        self.dns_stats_label = ttk.Label(header_frame, text="", foreground=self.colors['cyan'])
        self.dns_stats_label.pack(side=tk.RIGHT, padx=10)

        # DNS Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('timestamp', 'type', 'domain', 'answer', 'rcode', 'source')
        self.dns_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                     style='Alerts.Treeview')

        self.dns_tree.heading('timestamp', text='Timestamp', command=lambda: self.sort_dns('timestamp'))
        self.dns_tree.heading('type', text='Type', command=lambda: self.sort_dns('type'))
        self.dns_tree.heading('domain', text='Domain', command=lambda: self.sort_dns('domain'))
        self.dns_tree.heading('answer', text='Answer', command=lambda: self.sort_dns('answer'))
        self.dns_tree.heading('rcode', text='RCode', command=lambda: self.sort_dns('rcode'))
        self.dns_tree.heading('source', text='Source IP', command=lambda: self.sort_dns('source'))

        # Sort state for DNS
        self.dns_sort_column = 'timestamp'
        self.dns_sort_reverse = True

        self.dns_tree.column('timestamp', width=140, minwidth=100)
        self.dns_tree.column('type', width=60, minwidth=50, anchor='center')
        self.dns_tree.column('domain', width=250, minwidth=150)
        self.dns_tree.column('answer', width=180, minwidth=100)
        self.dns_tree.column('rcode', width=80, minwidth=60, anchor='center')
        self.dns_tree.column('source', width=120, minwidth=100)

        # Scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.dns_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.dns_tree.xview)
        self.dns_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.dns_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Color tags
        self.dns_tree.tag_configure('error', foreground=self.colors['red'])
        self.dns_tree.tag_configure('nxdomain', foreground=self.colors['orange'])

        # Context menu binding
        self.dns_tree.bind('<Button-3>', self._show_dns_context_menu)
        self.dns_tree.bind('<Double-1>', self._show_dns_details)

    def create_clamav_overview_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰕑 AV")

        # Stats grid
        stats_frame = ttk.Frame(tab)
        stats_frame.pack(fill=tk.X, pady=10)

        self.clamav_stat_widgets = {}
        stats = [
            ('daemon', '󰒓 Daemon', self.colors['blue']),
            ('freshclam', '󰑐 Updates', self.colors['teal']),
            ('onaccess', '󰈈 On-Access', self.colors['purple']),
            ('signatures', '󰕑 Signatures', self.colors['cyan']),
            ('quarantine', '󰀦 Quarantine', self.colors['red']),
        ]

        for i, (key, label, color) in enumerate(stats):
            frame = tk.Frame(stats_frame, bg=self.colors['bg_alt'], padx=15, pady=10)
            frame.grid(row=0, column=i, padx=5, pady=5, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)

            tk.Label(frame, text=label, font=('Hack Nerd Font', 10),
                    bg=self.colors['bg_alt'], fg=color).pack()
            status_label = tk.Label(frame, text="--", font=('Hack Nerd Font', 14, 'bold'),
                                   bg=self.colors['bg_alt'], fg=self.colors['fg'])
            status_label.pack()
            self.clamav_stat_widgets[key] = status_label

        # Scan info section
        info_frame = ttk.LabelFrame(tab, text="Scan Information", padding="10")
        info_frame.pack(fill=tk.X, pady=10)

        self.clamav_info_text = self.widgets.create_textbox(info_frame, height=8,
                                                           bg=self.colors['bg_alt'],
                                                           fg=self.colors['fg'],
                                                           font=('Hack Nerd Font', 9),
                                                           insertbackground=self.colors['fg'])
        self.clamav_info_text.pack(fill=tk.BOTH, expand=True)

        # Recent detections
        detect_label = ttk.Label(tab, text="Recent Detections", style='Title.TLabel')
        detect_label.pack(anchor=tk.W, pady=(10, 5))

        # Use ScrolledText directly for tag_configure support (CTkTextbox doesn't support it)
        self.clamav_detect_text = scrolledtext.ScrolledText(tab, height=10,
                                                             bg=self.colors['bg_alt'],
                                                             fg=self.colors['fg'],
                                                             font=('Hack Nerd Font', 9),
                                                             insertbackground=self.colors['fg'])
        self.clamav_detect_text.pack(fill=tk.BOTH, expand=True)
        self.clamav_detect_text.tag_configure('threat', foreground=self.colors['red'])
        self.clamav_detect_text.tag_configure('info', foreground=self.colors['cyan'])

    def create_clamav_quarantine_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰀦 Quar")

        # Header with actions
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="Quarantined Files", style='Title.TLabel').pack(side=tk.LEFT)
        self.widgets.create_button(header_frame, text="󰑐 Refresh", command=self.refresh_quarantine).pack(side=tk.RIGHT, padx=5)
        self.widgets.create_button(header_frame, text="󰃢 Clean All", command=self.clean_quarantine).pack(side=tk.RIGHT, padx=5)
        self.quarantine_delete_btn = self.widgets.create_button(header_frame, text="󰆴 Delete Selected",
                                                 command=self.delete_quarantine_file)
        self.quarantine_delete_btn.pack(side=tk.RIGHT, padx=5)
        self.create_tooltip(self.quarantine_delete_btn, "Permanently delete selected file")

        self.quarantine_restore_btn = self.widgets.create_button(header_frame, text="󰁯 Restore Selected",
                                                  command=self.restore_quarantine_file)
        self.quarantine_restore_btn.pack(side=tk.RIGHT, padx=5)
        self.create_tooltip(self.quarantine_restore_btn, "Restore file to original location")

        # Quarantine Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('date', 'filename', 'size', 'original_path')
        self.quarantine_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                            style='Alerts.Treeview')

        self.quarantine_tree.heading('date', text='Quarantined', command=lambda: self.sort_quarantine('date'))
        self.quarantine_tree.heading('filename', text='Filename', command=lambda: self.sort_quarantine('filename'))
        self.quarantine_tree.heading('size', text='Size', command=lambda: self.sort_quarantine('size'))
        self.quarantine_tree.heading('original_path', text='Original Path', command=lambda: self.sort_quarantine('original_path'))

        # Sort state for quarantine
        self.quarantine_sort_column = 'date'
        self.quarantine_sort_reverse = True

        self.quarantine_tree.column('date', width=140, minwidth=100)
        self.quarantine_tree.column('filename', width=200, minwidth=100)
        self.quarantine_tree.column('size', width=80, minwidth=60)
        self.quarantine_tree.column('original_path', width=400, minwidth=200)

        # Scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.quarantine_tree.xview)
        self.quarantine_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.quarantine_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Right-click context menu
        self.quarantine_tree.bind('<Button-3>', self.show_quarantine_context_menu)

        # Store quarantine data
        self.quarantine_data = {}

    def create_clamav_scan_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰈈 Scan")

        # Scan controls
        control_frame = ttk.LabelFrame(tab, text="Manual Scan", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Path selection
        path_frame = ttk.Frame(control_frame)
        path_frame.pack(fill=tk.X, pady=5)

        self.widgets.create_label(path_frame, text="Path:").pack(side=tk.LEFT, padx=(0, 10))
        self.scan_path_var = tk.StringVar(value=os.path.expanduser("~/Downloads"))
        self.scan_path_entry = self.widgets.create_entry(path_frame, textvariable=self.scan_path_var, width=50)
        self.scan_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.widgets.create_button(path_frame, text="󰉋 Browse", command=self.browse_scan_path).pack(side=tk.LEFT)

        # Quick scan buttons
        quick_frame = ttk.Frame(control_frame)
        quick_frame.pack(fill=tk.X, pady=10)

        self.widgets.create_label(quick_frame, text="Quick Scan:").pack(side=tk.LEFT, padx=(0, 10))
        self.widgets.create_button(quick_frame, text="󰉋 Downloads",
                   command=lambda: self.start_scan(os.path.expanduser("~/Downloads"))).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(quick_frame, text="󰉌 Documents",
                   command=lambda: self.start_scan(os.path.expanduser("~/Documents"))).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(quick_frame, text="󰗀 /tmp",
                   command=lambda: self.start_scan("/tmp")).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(quick_frame, text="󰋜 Home",
                   command=lambda: self.start_scan(os.path.expanduser("~"))).pack(side=tk.LEFT, padx=2)

        # Start scan button
        scan_btn_frame = ttk.Frame(control_frame)
        scan_btn_frame.pack(fill=tk.X, pady=10)

        self.scan_btn = self.widgets.create_button(scan_btn_frame, text="󰈈 Start Scan", command=self.start_custom_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_scan_btn = self.widgets.create_button(scan_btn_frame, text="󰅖 Cancel", command=self.cancel_scan)
        self.cancel_scan_btn.pack(side=tk.LEFT, padx=5)
        self.cancel_scan_btn.configure(state='disabled')
        self.create_tooltip(self.cancel_scan_btn, "Cancel running scan")

        self.scan_status_label = ttk.Label(scan_btn_frame, text="Ready")
        self.scan_status_label.pack(side=tk.LEFT, padx=10)

        # Scan output
        output_label = ttk.Label(tab, text="Scan Output", style='Title.TLabel')
        output_label.pack(anchor=tk.W, pady=(10, 5))

        # Use ScrolledText directly for tag_configure support (CTkTextbox doesn't support it)
        self.scan_output_text = scrolledtext.ScrolledText(tab, height=15,
                                                           bg=self.colors['bg_alt'],
                                                           fg=self.colors['fg'],
                                                           font=('Hack Nerd Font', 9),
                                                           insertbackground=self.colors['fg'])
        self.scan_output_text.pack(fill=tk.BOTH, expand=True)
        self.scan_output_text.tag_configure('infected', foreground=self.colors['red'])
        self.scan_output_text.tag_configure('clean', foreground=self.colors['green'])
        self.scan_output_text.tag_configure('info', foreground=self.colors['cyan'])

    def create_analytics_tab(self):
        """Phase 6: Analytics and Visualization tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰄧 Stats")

        if not MATPLOTLIB_AVAILABLE:
            ttk.Label(tab, text="Install matplotlib for charts: pip install matplotlib",
                     font=('Hack Nerd Font', 11)).pack(pady=20)
            return

        # Create scrollable canvas for analytics
        canvas = tk.Canvas(tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Time range controls for Stats
        time_frame = ttk.Frame(scrollable_frame)
        time_frame.pack(fill=tk.X, pady=(5, 10), padx=5)

        ttk.Label(time_frame, text="󰅐 Time Range:", font=('Hack Nerd Font', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 10))

        # Stats time range variable
        self.stats_time_range = tk.StringVar(value='24h')

        self.widgets.create_button(time_frame, text="1h", width=5,
                    command=lambda: self._set_stats_time_range('1h')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="6h", width=5,
                    command=lambda: self._set_stats_time_range('6h')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="24h", width=5,
                    command=lambda: self._set_stats_time_range('24h')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="7d", width=5,
                    command=lambda: self._set_stats_time_range('7d')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(time_frame, text="30d", width=5,
                    command=lambda: self._set_stats_time_range('30d')).pack(side=tk.LEFT, padx=2)

        self.stats_time_label = ttk.Label(time_frame, text="Showing: Last 24 hours", foreground=self.colors['cyan'])
        self.stats_time_label.pack(side=tk.LEFT, padx=(15, 0))

        # Alert Trends Chart
        self.trends_label_frame = ttk.LabelFrame(scrollable_frame, text="󰄧 Alert Trends (Last 24 Hours)", padding="10")
        self.trends_label_frame.pack(fill=tk.X, pady=10, padx=5)

        self.trends_figure = Figure(figsize=(9, 3), dpi=100, facecolor=self.colors['bg'])
        self.trends_ax = self.trends_figure.add_subplot(111)
        self.trends_ax.set_facecolor(self.colors['bg_alt'])
        self.trends_canvas = FigureCanvasTkAgg(self.trends_figure, self.trends_label_frame)
        self.trends_canvas.get_tk_widget().pack(fill=tk.X)

        # Protocol Distribution Chart
        proto_frame = ttk.LabelFrame(scrollable_frame, text="󰖟 Protocol Distribution", padding="10")
        proto_frame.pack(fill=tk.X, pady=10, padx=5)

        self.proto_figure = Figure(figsize=(9, 3), dpi=100, facecolor=self.colors['bg'])
        self.proto_ax = self.proto_figure.add_subplot(111)
        self.proto_ax.set_facecolor(self.colors['bg_alt'])
        self.proto_canvas = FigureCanvasTkAgg(self.proto_figure, proto_frame)
        self.proto_canvas.get_tk_widget().pack(fill=tk.X)

        # Top Talkers Chart
        talkers_frame = ttk.LabelFrame(scrollable_frame, text="󰒍 Top Talkers", padding="10")
        talkers_frame.pack(fill=tk.X, pady=10, padx=5)

        self.talkers_figure = Figure(figsize=(9, 3), dpi=100, facecolor=self.colors['bg'])
        self.talkers_ax = self.talkers_figure.add_subplot(111)
        self.talkers_ax.set_facecolor(self.colors['bg_alt'])
        self.talkers_canvas = FigureCanvasTkAgg(self.talkers_figure, talkers_frame)
        self.talkers_canvas.get_tk_widget().pack(fill=tk.X)

        # GeoIP Section
        geo_frame = ttk.LabelFrame(scrollable_frame, text="󰍎 Geographic Distribution", padding="10")
        geo_frame.pack(fill=tk.X, pady=10, padx=5)

        if GEOIP_AVAILABLE:
            self.geo_text = self.widgets.create_textbox(geo_frame, height=8,
                                                       bg=self.colors['bg_alt'],
                                                       fg=self.colors['fg'],
                                                       font=('Hack Nerd Font', 9))
            self.geo_text.pack(fill=tk.X)
        else:
            ttk.Label(geo_frame, text="Install geoip2 for geographic data: pip install geoip2").pack()
            self.geo_text = None

        # Refresh button
        self.widgets.create_button(scrollable_frame, text="󰑐 Refresh Analytics",
                   command=self.refresh_analytics).pack(pady=10)

        # Initial refresh
        self.root.after(1000, self.refresh_analytics)

    def create_suricata_settings_tab(self):
        """Comprehensive Suricata IDS settings"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰒃 IDS")

        # Create scrollable frame
        canvas = tk.Canvas(tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Service Control
        service_frame = ttk.LabelFrame(scrollable_frame, text="󰒃 Service Control", padding="10")
        service_frame.pack(fill=tk.X, pady=5, padx=5)

        self.service_info = ttk.Label(service_frame, text="Loading...")
        self.service_info.pack(anchor=tk.W, pady=(0, 10))

        svc_btns = ttk.Frame(service_frame)
        svc_btns.pack(fill=tk.X)
        self.widgets.create_button(svc_btns, text="󰐊 Start", command=self.start_ids).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(svc_btns, text="󰓛 Stop", command=self.stop_ids).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(svc_btns, text="󰑐 Restart", command=self.restart_ids).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(svc_btns, text="󰈙 View Logs", command=self.view_logs).pack(side=tk.LEFT, padx=2)

        # Rule Management
        rules_frame = ttk.LabelFrame(scrollable_frame, text="󰌆 Rule Management", padding="10")
        rules_frame.pack(fill=tk.X, pady=5, padx=5)

        # Rule Sources Treeview
        rule_info = ttk.Frame(rules_frame)
        rule_info.pack(fill=tk.X, pady=5)
        self.widgets.create_label(rule_info, text="Rule Sources (click to toggle):").pack(anchor=tk.W)

        # Create Treeview for rule sources
        tree_frame = ttk.Frame(rule_info)
        tree_frame.pack(fill=tk.X, pady=5)

        columns = ('status', 'source', 'vendor', 'license')
        self.rule_sources_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                               style='Alerts.Treeview', height=6)
        self.rule_sources_tree.heading('status', text='Status', command=lambda: self.sort_rule_sources('status'))
        self.rule_sources_tree.heading('source', text='Source', command=lambda: self.sort_rule_sources('source'))
        self.rule_sources_tree.heading('vendor', text='Vendor', command=lambda: self.sort_rule_sources('vendor'))
        self.rule_sources_tree.heading('license', text='License', command=lambda: self.sort_rule_sources('license'))

        # Sort state for rule sources
        self.rule_sources_sort_column = 'source'
        self.rule_sources_sort_reverse = False

        self.rule_sources_tree.column('status', width=80, anchor='center')
        self.rule_sources_tree.column('source', width=200)
        self.rule_sources_tree.column('vendor', width=100)
        self.rule_sources_tree.column('license', width=80)

        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.rule_sources_tree.yview)
        self.rule_sources_tree.configure(yscrollcommand=tree_scroll.set)
        self.rule_sources_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click to toggle source
        self.rule_sources_tree.bind('<Double-1>', self._toggle_rule_source)

        # Keep textbox for backward compatibility (hidden, used by refresh_suricata_status)
        self.rule_sources_text = self.widgets.create_textbox(rule_info, height=1,
                                                            bg=self.colors['bg_alt'],
                                                            fg=self.colors['fg'],
                                                            font=('Hack Nerd Font', 9))
        # Hide the old textbox
        # self.rule_sources_text.pack(fill=tk.X, pady=5)

        # First row of buttons - source management
        rule_btns = ttk.Frame(rules_frame)
        rule_btns.pack(fill=tk.X, pady=(0, 5))
        self.widgets.create_button(rule_btns, text="󰄬 Enable Selected", command=self._enable_selected_source).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(rule_btns, text="󰅖 Disable Selected", command=self._disable_selected_source).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(rule_btns, text="󰒃 Enable Recommended", command=self._enable_recommended_sources).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(rule_btns, text="󰇙 Refresh", command=self._refresh_rule_sources).pack(side=tk.LEFT, padx=2)

        # Second row - rule update/management
        rule_btns2 = ttk.Frame(rules_frame)
        rule_btns2.pack(fill=tk.X)
        self.widgets.create_button(rule_btns2, text="󰑐 Update Rules", command=self.update_rules).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(rule_btns2, text="󰃢 Disable SID", command=self.disable_rule_dialog).pack(side=tk.LEFT, padx=2)

        # Network Interface
        iface_frame = ttk.LabelFrame(scrollable_frame, text="󰖟 Network Interface", padding="10")
        iface_frame.pack(fill=tk.X, pady=5, padx=5)

        iface_row = ttk.Frame(iface_frame)
        iface_row.pack(fill=tk.X, pady=5)
        self.widgets.create_label(iface_row, text="Interface:").pack(side=tk.LEFT, padx=(0, 10))
        self.iface_var = tk.StringVar(value="wlp8s0")
        self.iface_combo = ttk.Combobox(iface_row, textvariable=self.iface_var, width=20)
        self.iface_combo.pack(side=tk.LEFT)
        self.widgets.create_button(iface_row, text="󰑐 Detect", command=self.detect_interfaces).pack(side=tk.LEFT, padx=5)

        # Current interface status from config
        self.iface_status_label = ttk.Label(iface_frame, text="Current config: loading...", foreground=self.colors['gray'])
        self.iface_status_label.pack(anchor=tk.W, pady=(5, 0))

        # Logging Options
        log_frame = ttk.LabelFrame(scrollable_frame, text="󰈙 Logging Options", padding="10")
        log_frame.pack(fill=tk.X, pady=5, padx=5)

        self.eve_json_var = tk.BooleanVar(value=True)
        self.fast_log_var = tk.BooleanVar(value=True)
        self.stats_log_var = tk.BooleanVar(value=False)
        self.pcap_log_var = tk.BooleanVar(value=False)

        self.widgets.create_checkbox(log_frame, text="EVE JSON (alerts, http, dns, tls, etc.)",
                       variable=self.eve_json_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(log_frame, text="Fast Log (quick alert summary)",
                       variable=self.fast_log_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(log_frame, text="Stats Log (performance metrics)",
                       variable=self.stats_log_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(log_frame, text="PCAP Logging (packet capture - disk intensive!)",
                       variable=self.pcap_log_var).pack(anchor=tk.W)

        log_btns = ttk.Frame(log_frame)
        log_btns.pack(fill=tk.X, pady=(10, 0))
        self.widgets.create_button(log_btns, text="󰃢 Clean Logs", command=self.clean_logs).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(log_btns, text="󰈙 Open Log Dir", command=self.view_logs).pack(side=tk.LEFT, padx=2)

        # Performance Tuning
        perf_frame = ttk.LabelFrame(scrollable_frame, text="󰓅 Performance Tuning", padding="10")
        perf_frame.pack(fill=tk.X, pady=5, padx=5)

        # Runmode
        runmode_row = ttk.Frame(perf_frame)
        runmode_row.pack(fill=tk.X, pady=2)
        self.widgets.create_label(runmode_row, text="Run Mode:").pack(side=tk.LEFT, padx=(0, 10))
        self.runmode_var = tk.StringVar(value="autofp")
        ttk.Radiobutton(runmode_row, text="AutoFP (default)", variable=self.runmode_var,
                       value="autofp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(runmode_row, text="Workers", variable=self.runmode_var,
                       value="workers").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(runmode_row, text="Single", variable=self.runmode_var,
                       value="single").pack(side=tk.LEFT, padx=5)

        # Thread count
        thread_row = ttk.Frame(perf_frame)
        thread_row.pack(fill=tk.X, pady=2)
        self.widgets.create_label(thread_row, text="Detection Threads:").pack(side=tk.LEFT, padx=(0, 10))
        self.thread_var = tk.StringVar(value="auto")
        self.widgets.create_entry(thread_row, textvariable=self.thread_var, width=10).pack(side=tk.LEFT)
        self.widgets.create_label(thread_row, text="(auto = CPU count)").pack(side=tk.LEFT, padx=5)

        # JA3/JA4 TLS Fingerprinting
        ja_frame = ttk.LabelFrame(scrollable_frame, text="󰒃 TLS Fingerprinting (JA3/JA4)", padding="10")
        ja_frame.pack(fill=tk.X, pady=5, padx=5)

        ja_info = ttk.Label(ja_frame,
            text="JA3/JA4 fingerprints detect malware based on TLS client hello patterns.\n"
                 "Required for abuse.ch/sslbl-ja3 rules. Minor performance impact.",
            foreground=self.colors['gray'])
        ja_info.pack(anchor=tk.W, pady=(0, 5))

        ja_checkboxes = ttk.Frame(ja_frame)
        ja_checkboxes.pack(fill=tk.X, pady=5)

        self.ja3_enabled_var = tk.BooleanVar(value=False)
        self.ja4_enabled_var = tk.BooleanVar(value=False)

        self.widgets.create_checkbox(ja_checkboxes, text="Enable JA3 fingerprints (TLS 1.2)",
                        variable=self.ja3_enabled_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(ja_checkboxes, text="Enable JA4 fingerprints (TLS 1.3 & QUIC)",
                        variable=self.ja4_enabled_var).pack(anchor=tk.W)

        ja_btns = ttk.Frame(ja_frame)
        ja_btns.pack(fill=tk.X, pady=(5, 0))
        self.widgets.create_button(ja_btns, text="󰇙 Check Status", command=self._check_ja_status).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(ja_btns, text="󰄬 Apply JA3/JA4 Config", command=self._apply_ja_config).pack(side=tk.LEFT, padx=2)

        self.ja_status_label = ttk.Label(ja_frame, text="", foreground=self.colors['gray'])
        self.ja_status_label.pack(anchor=tk.W, pady=(5, 0))

        # Configuration File
        config_frame = ttk.LabelFrame(scrollable_frame, text="󰈔 Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=5, padx=5)

        config_btns = ttk.Frame(config_frame)
        config_btns.pack(fill=tk.X)
        self.widgets.create_button(config_btns, text="󰈔 Edit suricata.yaml", command=self.open_config).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(config_btns, text="󰋼 Test Config", command=self.test_suricata_config).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(config_btns, text="󰑐 Reload Rules", command=self.reload_suricata_rules).pack(side=tk.LEFT, padx=2)

        # Apply Changes Button (sticky at bottom)
        apply_frame = ttk.Frame(scrollable_frame)
        apply_frame.pack(fill=tk.X, pady=10, padx=5)

        self.ids_apply_btn = self.widgets.create_button(apply_frame, text="󰄬 Apply Changes & Restart IDS",
                                        command=self.apply_ids_settings)
        self.ids_apply_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.ids_apply_btn, "Apply all IDS configuration changes and restart service")

        self.ids_changes_label = ttk.Label(apply_frame, text="", foreground=self.colors['yellow'])
        self.ids_changes_label.pack(side=tk.LEFT, padx=10)

        # Deployment
        deploy_frame = ttk.LabelFrame(scrollable_frame, text="󰒃 Deployment", padding="10")
        deploy_frame.pack(fill=tk.X, pady=5, padx=5)

        self.widgets.create_button(deploy_frame, text="󰒃 Full Deploy/Reinstall",
                   command=self.deploy_suricata).pack(side=tk.LEFT, padx=2)

        # Load current settings
        self.root.after(500, self.load_suricata_settings)

    def create_clamav_settings_tab(self):
        """Comprehensive ClamAV settings"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰕑 AVcfg")

        # Create scrollable frame
        canvas = tk.Canvas(tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Service Control
        service_frame = ttk.LabelFrame(scrollable_frame, text="󰕑 Service Control", padding="10")
        service_frame.pack(fill=tk.X, pady=5, padx=5)

        self.clamav_service_info = ttk.Label(service_frame, text="Loading...")
        self.clamav_service_info.pack(anchor=tk.W, pady=(0, 10))

        svc_grid = ttk.Frame(service_frame)
        svc_grid.pack(fill=tk.X)

        # Daemon controls
        daemon_row = ttk.Frame(svc_grid)
        daemon_row.pack(fill=tk.X, pady=2)
        ttk.Label(daemon_row, text="ClamD (Daemon):", width=20).pack(side=tk.LEFT)
        self.widgets.create_button(daemon_row, text="Start", command=lambda: self.control_clamav_service('clamav-daemon', 'start')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(daemon_row, text="Stop", command=lambda: self.control_clamav_service('clamav-daemon', 'stop')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(daemon_row, text="Restart", command=lambda: self.control_clamav_service('clamav-daemon', 'restart')).pack(side=tk.LEFT, padx=2)

        # Freshclam controls
        fresh_row = ttk.Frame(svc_grid)
        fresh_row.pack(fill=tk.X, pady=2)
        ttk.Label(fresh_row, text="Freshclam (Updates):", width=20).pack(side=tk.LEFT)
        self.widgets.create_button(fresh_row, text="Start", command=lambda: self.control_clamav_service('clamav-freshclam', 'start')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(fresh_row, text="Stop", command=lambda: self.control_clamav_service('clamav-freshclam', 'stop')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(fresh_row, text="Restart", command=lambda: self.control_clamav_service('clamav-freshclam', 'restart')).pack(side=tk.LEFT, padx=2)

        # On-Access controls
        onacc_row = ttk.Frame(svc_grid)
        onacc_row.pack(fill=tk.X, pady=2)
        ttk.Label(onacc_row, text="On-Access Scanner:", width=20).pack(side=tk.LEFT)
        self.widgets.create_button(onacc_row, text="Start", command=lambda: self.control_clamav_service('clamav-clamonacc', 'start')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(onacc_row, text="Stop", command=lambda: self.control_clamav_service('clamav-clamonacc', 'stop')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(onacc_row, text="Restart", command=lambda: self.control_clamav_service('clamav-clamonacc', 'restart')).pack(side=tk.LEFT, padx=2)

        # Signature Updates
        sig_frame = ttk.LabelFrame(scrollable_frame, text="󰕑 Signature Updates", padding="10")
        sig_frame.pack(fill=tk.X, pady=5, padx=5)

        self.sig_info_label = ttk.Label(sig_frame, text="Signature database info loading...")
        self.sig_info_label.pack(anchor=tk.W, pady=(0, 10))

        sig_btns = ttk.Frame(sig_frame)
        sig_btns.pack(fill=tk.X)
        self.widgets.create_button(sig_btns, text="󰑐 Update Now", command=self.update_signatures).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(sig_btns, text="󰈙 View Update Log", command=self.view_freshclam_log).pack(side=tk.LEFT, padx=2)

        # Update frequency
        freq_row = ttk.Frame(sig_frame)
        freq_row.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(freq_row, text="Update Frequency:").pack(side=tk.LEFT, padx=(0, 10))
        self.update_freq_var = tk.StringVar(value="24")
        freq_combo = ttk.Combobox(freq_row, textvariable=self.update_freq_var,
                                  values=["1", "2", "4", "6", "12", "24"], width=10)
        freq_combo.pack(side=tk.LEFT)
        ttk.Label(freq_row, text="checks per day").pack(side=tk.LEFT, padx=5)

        # Scan Settings
        scan_frame = ttk.LabelFrame(scrollable_frame, text="󰈈 Scan Settings", padding="10")
        scan_frame.pack(fill=tk.X, pady=5, padx=5)

        # Scan options
        self.scan_recursive_var = tk.BooleanVar(value=True)
        self.scan_archive_var = tk.BooleanVar(value=True)
        self.scan_ole2_var = tk.BooleanVar(value=True)
        self.scan_pdf_var = tk.BooleanVar(value=True)
        self.scan_html_var = tk.BooleanVar(value=True)
        self.scan_mail_var = tk.BooleanVar(value=True)
        self.heuristic_var = tk.BooleanVar(value=True)

        scan_opts_left = ttk.Frame(scan_frame)
        scan_opts_left.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.widgets.create_checkbox(scan_opts_left, text="Recursive scanning",
                       variable=self.scan_recursive_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(scan_opts_left, text="Scan archives (zip, rar, etc.)",
                       variable=self.scan_archive_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(scan_opts_left, text="Scan OLE2 (Office docs)",
                       variable=self.scan_ole2_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(scan_opts_left, text="Scan PDF files",
                       variable=self.scan_pdf_var).pack(anchor=tk.W)

        scan_opts_right = ttk.Frame(scan_frame)
        scan_opts_right.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.widgets.create_checkbox(scan_opts_right, text="Scan HTML files",
                       variable=self.scan_html_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(scan_opts_right, text="Scan mail files",
                       variable=self.scan_mail_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(scan_opts_right, text="Heuristic detection",
                       variable=self.heuristic_var).pack(anchor=tk.W)

        # Size limits
        limit_frame = ttk.Frame(scan_frame)
        limit_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(limit_frame, text="Max file size (MB):").pack(side=tk.LEFT, padx=(0, 5))
        self.max_filesize_var = tk.StringVar(value="100")
        self.widgets.create_entry(limit_frame, textvariable=self.max_filesize_var, width=8).pack(side=tk.LEFT)

        ttk.Label(limit_frame, text="Max scan size (MB):").pack(side=tk.LEFT, padx=(20, 5))
        self.max_scansize_var = tk.StringVar(value="400")
        self.widgets.create_entry(limit_frame, textvariable=self.max_scansize_var, width=8).pack(side=tk.LEFT)

        # Service Persistence Settings
        persist_frame = ttk.LabelFrame(scrollable_frame, text="󰒓 Service Persistence", padding="10")
        persist_frame.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(persist_frame, text="Enable services to start automatically on boot:",
                  foreground=self.colors['gray']).pack(anchor=tk.W, pady=(0, 5))

        # Freshclam auto-updates
        self.freshclam_persist_var = tk.BooleanVar(value=False)
        self.widgets.create_checkbox(persist_frame, text="󰇚 Auto-update signatures on boot (clamav-freshclam service)",
                       variable=self.freshclam_persist_var).pack(anchor=tk.W)

        # On-access scanning persistence
        self.onacc_persist_var = tk.BooleanVar(value=False)
        self.widgets.create_checkbox(persist_frame, text="󰈈 Real-time protection on boot (clamav-clamonacc service)",
                       variable=self.onacc_persist_var).pack(anchor=tk.W)

        # Status indicator row
        persist_status_row = ttk.Frame(persist_frame)
        persist_status_row.pack(fill=tk.X, pady=(10, 0))
        self.freshclam_persist_status = ttk.Label(persist_status_row, text="", foreground=self.colors['gray'])
        self.freshclam_persist_status.pack(side=tk.LEFT, padx=(0, 20))
        self.onacc_persist_status = ttk.Label(persist_status_row, text="", foreground=self.colors['gray'])
        self.onacc_persist_status.pack(side=tk.LEFT)

        # On-Access Settings (runtime)
        onacc_frame = ttk.LabelFrame(scrollable_frame, text="󰈈 On-Access Scanning (Current Session)", padding="10")
        onacc_frame.pack(fill=tk.X, pady=5, padx=5)

        self.onacc_enabled_var = tk.BooleanVar(value=False)
        self.widgets.create_checkbox(onacc_frame, text="Enable On-Access scanning now (real-time protection)",
                       variable=self.onacc_enabled_var).pack(anchor=tk.W)

        # Watch paths
        watch_row = ttk.Frame(onacc_frame)
        watch_row.pack(fill=tk.X, pady=5)
        ttk.Label(watch_row, text="Watch paths:").pack(anchor=tk.W)
        self.watch_paths_text = self.widgets.create_textbox(watch_row, height=3,
                                                           bg=self.colors['bg_alt'],
                                                           fg=self.colors['fg'],
                                                           font=('Hack Nerd Font', 9))
        self.watch_paths_text.pack(fill=tk.X)
        self.watch_paths_text.insert(tk.END, "/home\n/tmp\n/var/tmp")

        # Exclusions
        excl_row = ttk.Frame(onacc_frame)
        excl_row.pack(fill=tk.X, pady=5)
        ttk.Label(excl_row, text="Exclude paths:").pack(anchor=tk.W)
        self.excl_paths_text = self.widgets.create_textbox(excl_row, height=3,
                                                          bg=self.colors['bg_alt'],
                                                          fg=self.colors['fg'],
                                                          font=('Hack Nerd Font', 9))
        self.excl_paths_text.pack(fill=tk.X)
        self.excl_paths_text.insert(tk.END, "/home/*/.cache\n/home/*/.local/share/Trash")

        # Quarantine Settings
        quar_frame = ttk.LabelFrame(scrollable_frame, text="󰀦 Quarantine Settings", padding="10")
        quar_frame.pack(fill=tk.X, pady=5, padx=5)

        quar_row = ttk.Frame(quar_frame)
        quar_row.pack(fill=tk.X)
        ttk.Label(quar_row, text="Quarantine directory:").pack(side=tk.LEFT, padx=(0, 5))
        self.quarantine_dir_var = tk.StringVar(value="/var/lib/clamav/quarantine")
        self.widgets.create_entry(quar_row, textvariable=self.quarantine_dir_var, width=40).pack(side=tk.LEFT)
        self.widgets.create_button(quar_row, text="󰉋 Browse", command=self.browse_quarantine_dir).pack(side=tk.LEFT, padx=5)

        self.move_to_quarantine_var = tk.BooleanVar(value=True)
        self.widgets.create_checkbox(quar_frame, text="Move infected files to quarantine (vs. just report)",
                       variable=self.move_to_quarantine_var).pack(anchor=tk.W, pady=5)

        # Scheduled Scans Section
        sched_frame = ttk.LabelFrame(scrollable_frame, text="󰃰 Scheduled Scans", padding="10")
        sched_frame.pack(fill=tk.X, pady=5, padx=5)

        # Enable/disable scheduled scans
        self.scheduled_scan_enabled = tk.BooleanVar(value=False)
        self.widgets.create_checkbox(sched_frame, text="Enable scheduled scans (uses systemd timer)",
                       variable=self.scheduled_scan_enabled).pack(anchor=tk.W)

        # Schedule configuration
        sched_config = ttk.Frame(sched_frame)
        sched_config.pack(fill=tk.X, pady=(10, 5))

        ttk.Label(sched_config, text="Frequency:").pack(side=tk.LEFT, padx=(0, 5))
        self.scan_frequency_var = tk.StringVar(value="daily")
        freq_combo = ttk.Combobox(sched_config, textvariable=self.scan_frequency_var,
                                  values=["daily", "weekly", "monthly"], width=10, state='readonly')
        freq_combo.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(sched_config, text="Time:").pack(side=tk.LEFT, padx=(0, 5))
        self.scan_time_var = tk.StringVar(value="02:00")
        time_entry = self.widgets.create_entry(sched_config, textvariable=self.scan_time_var, width=8)
        time_entry.pack(side=tk.LEFT, padx=(0, 15))
        self.create_tooltip(time_entry, "24-hour format (HH:MM)")

        ttk.Label(sched_config, text="Day:").pack(side=tk.LEFT, padx=(0, 5))
        self.scan_day_var = tk.StringVar(value="Sun")
        day_combo = ttk.Combobox(sched_config, textvariable=self.scan_day_var,
                                 values=["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
                                 width=6, state='readonly')
        day_combo.pack(side=tk.LEFT)
        self.create_tooltip(day_combo, "Only applies to weekly scans")

        # Scan targets
        targets_row = ttk.Frame(sched_frame)
        targets_row.pack(fill=tk.X, pady=5)
        ttk.Label(targets_row, text="Scan directories (one per line):").pack(anchor=tk.W)
        self.scheduled_scan_paths = self.widgets.create_textbox(targets_row, height=3,
                                                                bg=self.colors['bg_alt'],
                                                                fg=self.colors['fg'],
                                                                font=('Hack Nerd Font', 9))
        self.scheduled_scan_paths.pack(fill=tk.X)
        self.scheduled_scan_paths.insert(tk.END, "/home\n/tmp\n/var/tmp")

        # Notification options
        notify_row = ttk.Frame(sched_frame)
        notify_row.pack(fill=tk.X, pady=5)
        self.scan_notify_desktop = tk.BooleanVar(value=True)
        self.scan_notify_log = tk.BooleanVar(value=True)
        self.widgets.create_checkbox(notify_row, text="Desktop notification on findings",
                       variable=self.scan_notify_desktop).pack(side=tk.LEFT, padx=(0, 15))
        self.widgets.create_checkbox(notify_row, text="Write to log file",
                       variable=self.scan_notify_log).pack(side=tk.LEFT)

        # Schedule control buttons
        sched_btns = ttk.Frame(sched_frame)
        sched_btns.pack(fill=tk.X, pady=(10, 5))
        self.widgets.create_button(sched_btns, text="󰄬 Apply Schedule",
                                   command=self._apply_scheduled_scan).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(sched_btns, text="󰅖 Remove Schedule",
                                   command=self._remove_scheduled_scan).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(sched_btns, text="󰋚 Check Status",
                                   command=self._check_scheduled_scan_status).pack(side=tk.LEFT, padx=2)

        # Status label
        self.sched_scan_status = ttk.Label(sched_frame, text="Status: Not configured", foreground=self.colors['gray'])
        self.sched_scan_status.pack(anchor=tk.W, pady=(5, 0))

        # Configuration & Logs
        config_frame = ttk.LabelFrame(scrollable_frame, text="󰈔 Configuration & Logs", padding="10")
        config_frame.pack(fill=tk.X, pady=5, padx=5)

        config_btns = ttk.Frame(config_frame)
        config_btns.pack(fill=tk.X)
        self.widgets.create_button(config_btns, text="󰈔 Edit clamd.conf", command=self.edit_clamd_conf).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(config_btns, text="󰈔 Edit freshclam.conf", command=self.edit_freshclam_conf).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(config_btns, text="󰈙 View Logs", command=self.view_av_logs).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(config_btns, text="󰃢 Clean Logs", command=self.clean_av_logs).pack(side=tk.LEFT, padx=2)

        # Apply Changes Button (sticky at bottom)
        apply_frame = ttk.Frame(scrollable_frame)
        apply_frame.pack(fill=tk.X, pady=10, padx=5)

        self.av_apply_btn = self.widgets.create_button(apply_frame, text="󰄬 Apply Changes & Restart AV",
                                       command=self.apply_av_settings)
        self.av_apply_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.av_apply_btn, "Apply all AV configuration changes and restart services")

        self.av_changes_label = ttk.Label(apply_frame, text="", foreground=self.colors['yellow'])
        self.av_changes_label.pack(side=tk.LEFT, padx=10)

        # Deployment
        deploy_frame = ttk.LabelFrame(scrollable_frame, text="󰕑 Deployment", padding="10")
        deploy_frame.pack(fill=tk.X, pady=5, padx=5)

        self.widgets.create_button(deploy_frame, text="󰕑 Full Deploy/Reinstall",
                   command=self.deploy_clamav).pack(side=tk.LEFT, padx=2)

        # Load current settings
        self.root.after(500, self.load_clamav_settings)

    def create_threat_intel_tab(self):
        """Threat Intelligence configuration and lookup history"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰊕 Intel")

        # Create scrollable frame for content
        canvas = tk.Canvas(tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # API Status Section
        status_frame = ttk.LabelFrame(scrollable_frame, text="󰊕 API Status", padding="10")
        status_frame.pack(fill=tk.X, pady=10, padx=5)

        # VirusTotal status
        vt_row = ttk.Frame(status_frame)
        vt_row.pack(fill=tk.X, pady=5)
        ttk.Label(vt_row, text="VirusTotal:", width=15).pack(side=tk.LEFT)
        self.vt_status_label = ttk.Label(vt_row, text="Not configured", foreground=self.colors['gray'])
        self.vt_status_label.pack(side=tk.LEFT, padx=10)
        self.vt_quota_label = ttk.Label(vt_row, text="", foreground=self.colors['gray'])
        self.vt_quota_label.pack(side=tk.RIGHT)

        # OTX status
        otx_row = ttk.Frame(status_frame)
        otx_row.pack(fill=tk.X, pady=5)
        ttk.Label(otx_row, text="AlienVault OTX:", width=15).pack(side=tk.LEFT)
        self.otx_status_label = ttk.Label(otx_row, text="Not configured", foreground=self.colors['gray'])
        self.otx_status_label.pack(side=tk.LEFT, padx=10)

        # AbuseIPDB status
        abuseipdb_row = ttk.Frame(status_frame)
        abuseipdb_row.pack(fill=tk.X, pady=5)
        ttk.Label(abuseipdb_row, text="AbuseIPDB:", width=15).pack(side=tk.LEFT)
        self.abuseipdb_status_label = ttk.Label(abuseipdb_row, text="Not configured", foreground=self.colors['gray'])
        self.abuseipdb_status_label.pack(side=tk.LEFT, padx=10)

        # ThreatFox status (no API key needed)
        threatfox_row = ttk.Frame(status_frame)
        threatfox_row.pack(fill=tk.X, pady=5)
        ttk.Label(threatfox_row, text="ThreatFox:", width=15).pack(side=tk.LEFT)
        ttk.Label(threatfox_row, text="✓ Available (no API key required)", foreground=self.colors['green']).pack(side=tk.LEFT, padx=10)

        # API Key Configuration Section
        keys_frame = ttk.LabelFrame(scrollable_frame, text="󰌋 API Key Configuration", padding="10")
        keys_frame.pack(fill=tk.X, pady=10, padx=5)

        # VirusTotal API Key
        vt_key_frame = ttk.Frame(keys_frame)
        vt_key_frame.pack(fill=tk.X, pady=5)
        ttk.Label(vt_key_frame, text="VirusTotal API Key:", width=18).pack(side=tk.LEFT)
        self.vt_key_var = tk.StringVar()
        self.vt_key_entry = self.widgets.create_entry(vt_key_frame, textvariable=self.vt_key_var, width=50, show="•")
        self.vt_key_entry.pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(vt_key_frame, text="Show", width=6,
                   command=lambda: self._toggle_key_visibility(self.vt_key_entry)).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(vt_key_frame, text="Save", width=6,
                   command=lambda: self._save_api_key('virustotal', self.vt_key_var.get())).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(vt_key_frame, text="Test", width=6,
                   command=lambda: self._test_api_key('virustotal')).pack(side=tk.LEFT, padx=2)

        ttk.Label(keys_frame, text="Get free key: https://www.virustotal.com/gui/join-us",
                  foreground=self.colors['cyan']).pack(anchor=tk.W)

        # OTX API Key
        otx_key_frame = ttk.Frame(keys_frame)
        otx_key_frame.pack(fill=tk.X, pady=(15, 5))
        ttk.Label(otx_key_frame, text="OTX API Key:", width=18).pack(side=tk.LEFT)
        self.otx_key_var = tk.StringVar()
        self.otx_key_entry = self.widgets.create_entry(otx_key_frame, textvariable=self.otx_key_var, width=50, show="•")
        self.otx_key_entry.pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(otx_key_frame, text="Show", width=6,
                   command=lambda: self._toggle_key_visibility(self.otx_key_entry)).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(otx_key_frame, text="Save", width=6,
                   command=lambda: self._save_api_key('otx', self.otx_key_var.get())).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(otx_key_frame, text="Test", width=6,
                   command=lambda: self._test_api_key('otx')).pack(side=tk.LEFT, padx=2)

        ttk.Label(keys_frame, text="Get free key: https://otx.alienvault.com/api",
                  foreground=self.colors['cyan']).pack(anchor=tk.W)

        # AbuseIPDB API Key
        abuseipdb_key_frame = ttk.Frame(keys_frame)
        abuseipdb_key_frame.pack(fill=tk.X, pady=(15, 5))
        ttk.Label(abuseipdb_key_frame, text="AbuseIPDB API Key:", width=18).pack(side=tk.LEFT)
        self.abuseipdb_key_var = tk.StringVar()
        self.abuseipdb_key_entry = self.widgets.create_entry(abuseipdb_key_frame, textvariable=self.abuseipdb_key_var, width=50, show="•")
        self.abuseipdb_key_entry.pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(abuseipdb_key_frame, text="Show", width=6,
                   command=lambda: self._toggle_key_visibility(self.abuseipdb_key_entry)).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(abuseipdb_key_frame, text="Save", width=6,
                   command=lambda: self._save_api_key('abuseipdb', self.abuseipdb_key_var.get())).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(abuseipdb_key_frame, text="Test", width=6,
                   command=lambda: self._test_api_key('abuseipdb')).pack(side=tk.LEFT, padx=2)

        ttk.Label(keys_frame, text="Get free key: https://www.abuseipdb.com/account/api",
                  foreground=self.colors['cyan']).pack(anchor=tk.W)

        # ThreatFox note (no API key needed)
        ttk.Label(keys_frame, text="󰊕 ThreatFox: No API key required (public API)",
                  foreground=self.colors['green']).pack(anchor=tk.W, pady=(10, 0))

        # Security note
        if KEYRING_AVAILABLE:
            ttk.Label(keys_frame, text="󰌋 API keys stored securely in system keyring",
                      foreground=self.colors['green']).pack(anchor=tk.W, pady=(10, 0))
        else:
            ttk.Label(keys_frame, text="⚠ Install 'keyring' package for secure key storage",
                      foreground=self.colors['yellow']).pack(anchor=tk.W, pady=(10, 0))

        # Lookup History Section
        history_frame = ttk.LabelFrame(scrollable_frame, text="󰋚 Recent Lookups", padding="10")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=5)

        # Treeview for lookup history
        columns = ('time', 'indicator', 'source', 'result')
        self.lookup_tree = ttk.Treeview(history_frame, columns=columns, show='headings',
                                         style='Alerts.Treeview', height=8)
        self.lookup_tree.heading('time', text='Time', command=lambda: self.sort_lookup_history('time'))
        self.lookup_tree.heading('indicator', text='Indicator', command=lambda: self.sort_lookup_history('indicator'))
        self.lookup_tree.heading('source', text='Source', command=lambda: self.sort_lookup_history('source'))
        self.lookup_tree.heading('result', text='Result', command=lambda: self.sort_lookup_history('result'))

        # Sort state for lookup history
        self.lookup_sort_column = 'time'
        self.lookup_sort_reverse = True

        self.lookup_tree.column('time', width=150)
        self.lookup_tree.column('indicator', width=200)
        self.lookup_tree.column('source', width=100)
        self.lookup_tree.column('result', width=200)

        self.lookup_tree.pack(fill=tk.BOTH, expand=True, pady=5)

        # Lookup history storage
        self.lookup_history = []

        # Actions row
        action_row = ttk.Frame(history_frame)
        action_row.pack(fill=tk.X, pady=5)
        self.widgets.create_button(action_row, text="Clear History", command=self._clear_lookup_history).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(action_row, text="Clear Cache", command=self._clear_ti_cache).pack(side=tk.LEFT, padx=2)

        # Manual Lookup Section
        lookup_frame = ttk.LabelFrame(scrollable_frame, text="󰍉 Manual Lookup", padding="10")
        lookup_frame.pack(fill=tk.X, pady=10, padx=5)

        lookup_row = ttk.Frame(lookup_frame)
        lookup_row.pack(fill=tk.X)
        ttk.Label(lookup_row, text="IOC:").pack(side=tk.LEFT)
        self.manual_lookup_var = tk.StringVar()
        self.widgets.create_entry(lookup_row, textvariable=self.manual_lookup_var, width=40).pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(lookup_row, text="VirusTotal", command=self._manual_vt_lookup).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(lookup_row, text="OTX", command=self._manual_otx_lookup).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(lookup_row, text="ThreatFox", command=self._manual_threatfox_lookup).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(lookup_row, text="AbuseIPDB", command=self._manual_abuseipdb_lookup).pack(side=tk.LEFT, padx=2)

        ttk.Label(lookup_frame, text="Enter IP address, domain, or file hash",
                  foreground=self.colors['gray']).pack(anchor=tk.W, pady=(5, 0))

        # Initialize status and load persisted lookups
        self.root.after(100, self._refresh_ti_status)
        self.root.after(200, self._refresh_intel_from_tracker)

    def _toggle_key_visibility(self, entry):
        """Toggle password visibility for API key entry"""
        if entry.cget('show') == '•':
            entry.configure(show='')
        else:
            entry.configure(show='•')

    def _save_api_key(self, service: str, key: str):
        """Save API key and update client"""
        if not key.strip():
            messagebox.showwarning("Warning", "API key cannot be empty")
            return

        if self._set_api_key(service, key.strip()):
            # Update the client with new key
            if service == 'virustotal':
                self.vt_client.api_key = key.strip()
            elif service == 'otx':
                self.otx_client.api_key = key.strip()
            elif service == 'abuseipdb':
                self.abuseipdb_client.api_key = key.strip()
            messagebox.showinfo("Success", f"{service.title()} API key saved")
            self._refresh_ti_status()
        else:
            messagebox.showerror("Error", "Failed to save API key. Install 'keyring' package.")

    def _test_api_key(self, service: str):
        """Test API key by making a simple lookup"""
        def do_test():
            test_ip = "8.8.8.8"  # Google DNS - safe to lookup
            if service == 'virustotal':
                result = self.vt_client.lookup_ip(test_ip)
            elif service == 'abuseipdb':
                result = self.abuseipdb_client.lookup_ip(test_ip)
            else:
                result = self.otx_client.lookup_ip(test_ip)

            def show_result():
                self.hide_progress()
                if 'error' in result:
                    messagebox.showerror("Test Failed", f"API Error: {result['error']}")
                else:
                    messagebox.showinfo("Test Successful", f"{service.title()} API key is working!")
                self._refresh_ti_status()

            self.root.after(0, show_result)

        self.show_progress(f"Testing {service} API...")
        threading.Thread(target=do_test, daemon=True).start()

    def _refresh_ti_status(self):
        """Refresh threat intelligence API status"""
        vt_key = self._get_api_key('virustotal')
        if vt_key:
            self.vt_status_label.configure(text="✓ Configured", foreground=self.colors['green'])
            self.vt_key_var.set(vt_key)
        else:
            self.vt_status_label.configure(text="✗ Not configured", foreground=self.colors['red'])

        otx_key = self._get_api_key('otx')
        if otx_key:
            self.otx_status_label.configure(text="✓ Configured", foreground=self.colors['green'])
            self.otx_key_var.set(otx_key)
        else:
            self.otx_status_label.configure(text="✗ Not configured", foreground=self.colors['red'])

        abuseipdb_key = self._get_api_key('abuseipdb')
        if abuseipdb_key:
            self.abuseipdb_status_label.configure(text="✓ Configured", foreground=self.colors['green'])
            self.abuseipdb_key_var.set(abuseipdb_key)
        else:
            self.abuseipdb_status_label.configure(text="✗ Not configured", foreground=self.colors['red'])

    def _clear_lookup_history(self):
        """Clear the lookup history display"""
        for item in self.lookup_tree.get_children():
            self.lookup_tree.delete(item)
        self.lookup_history.clear()

    def _clear_ti_cache(self):
        """Clear threat intelligence cache"""
        self.vt_client.cache.clear()
        self.otx_client.cache.clear()
        self.threatfox_client.cache.clear()
        self.abuseipdb_client.cache.clear()
        messagebox.showinfo("Cache Cleared", "Threat intelligence cache has been cleared")

    def _refresh_intel_from_tracker(self):
        """Refresh the Intel tab lookup history from the persistent tracker.

        This populates the Intel tab with all lookups from the last 12 hours.
        """
        # Get all active lookups from tracker
        all_lookups = self.ip_tracker.get_all_lookups()

        # Update the treeview with tracker data
        for item in self.lookup_tree.get_children():
            self.lookup_tree.delete(item)

        self.lookup_history.clear()

        for lookup in all_lookups:
            ip = lookup['ip']
            timestamp = lookup['timestamp'][:19].replace('T', ' ')  # Format timestamp
            source = lookup['source']
            result = lookup['result']
            details = lookup.get('details', {})

            # Build result string based on source
            if result == 'error':
                result_str = f"✗ Error: {details.get('error', 'Unknown')[:30]}"
            elif source == 'AbuseIPDB':
                score = details.get('abuseConfidenceScore', 0)
                reports = details.get('totalReports', 0)
                if result == 'DANGER':
                    result_str = f"⚠ DANGER: {score}% ({reports} reports)"
                elif result == 'suspect':
                    result_str = f"⚡ Suspect: {score}% ({reports} reports)"
                else:
                    result_str = f"✓ Clean: {score}%"
            elif source == 'VirusTotal':
                mal = details.get('malicious', 0)
                result_str = f"{'⚠ ' + str(mal) + ' malicious' if mal > 0 else '✓ Clean'}"
            else:
                result_str = f"{result}"

            self.lookup_tree.insert('', 'end', values=(timestamp, ip, source, result_str))
            self.lookup_history.append({
                'time': timestamp,
                'indicator': ip,
                'source': source,
                'result': details,
                'result_str': result_str
            })

    def _add_to_lookup_history(self, indicator: str, source: str, result: dict):
        """Add a lookup to the history display"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if 'error' in result:
            result_str = f"Error: {result['error']}"
        elif source == 'VirusTotal':
            mal = result.get('malicious', 0)
            result_str = f"{'⚠ ' + str(mal) + ' malicious' if mal > 0 else '✓ Clean'}"
        elif source == 'ThreatFox':
            if result.get('found', False):
                malware = result.get('malware', 'Unknown')
                result_str = f"⚠ {malware}"
            else:
                result_str = "✓ Not found"
        elif source == 'AbuseIPDB':
            score = result.get('abuse_score', 0)
            result_str = f"{'⚠ Score: ' + str(score) + '%' if score > 0 else '✓ Clean'}"
        else:
            pulses = result.get('pulse_count', 0)
            result_str = f"{'⚠ ' + str(pulses) + ' pulses' if pulses > 0 else '✓ Clean'}"

        self.lookup_tree.insert('', 0, values=(timestamp, indicator, source, result_str))
        self.lookup_history.insert(0, {'time': timestamp, 'indicator': indicator,
                                        'source': source, 'result': result, 'result_str': result_str})

        # Keep only last 50 entries
        if len(self.lookup_history) > 50:
            self.lookup_tree.delete(self.lookup_tree.get_children()[-1])
            self.lookup_history.pop()

    def sort_lookup_history(self, column):
        """Sort lookup history by column"""
        if self.lookup_sort_column == column:
            self.lookup_sort_reverse = not self.lookup_sort_reverse
        else:
            self.lookup_sort_column = column
            self.lookup_sort_reverse = True
        self._refresh_lookup_tree()

    def _refresh_lookup_tree(self):
        """Refresh the lookup history treeview with current sort"""
        # Clear existing items
        for item in self.lookup_tree.get_children():
            self.lookup_tree.delete(item)

        # Sort the history
        sort_col = self.lookup_sort_column
        sorted_history = sorted(self.lookup_history,
                               key=lambda x: x.get(sort_col, '') if sort_col != 'result' else x.get('result_str', ''),
                               reverse=self.lookup_sort_reverse)

        # Repopulate
        for entry in sorted_history:
            self.lookup_tree.insert('', tk.END, values=(
                entry['time'],
                entry['indicator'],
                entry['source'],
                entry.get('result_str', '')
            ))

    def _manual_vt_lookup(self):
        """Perform manual VirusTotal lookup"""
        indicator = self.manual_lookup_var.get().strip()
        if not indicator:
            return

        def do_lookup():
            # Detect indicator type
            if re.match(r'^[a-fA-F0-9]{32,64}$', indicator):
                result = self.vt_client.lookup_hash(indicator)
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
                result = self.vt_client.lookup_ip(indicator)
            else:
                result = self.vt_client.lookup_domain(indicator)

            def show():
                self.hide_progress()
                self._add_to_lookup_history(indicator, 'VirusTotal', result)
                self._show_threat_intel_result("VirusTotal", indicator, result)

            self.root.after(0, show)

        self.show_progress("Looking up on VirusTotal...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def _manual_otx_lookup(self):
        """Perform manual OTX lookup"""
        indicator = self.manual_lookup_var.get().strip()
        if not indicator:
            return

        def do_lookup():
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
                result = self.otx_client.lookup_ip(indicator)
            else:
                result = self.otx_client.lookup_domain(indicator)

            def show():
                self.hide_progress()
                self._add_to_lookup_history(indicator, 'OTX', result)
                self._show_threat_intel_result("OTX", indicator, result)

            self.root.after(0, show)

        self.show_progress("Looking up on OTX...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def _manual_threatfox_lookup(self):
        """Perform manual ThreatFox lookup (no API key required)"""
        indicator = self.manual_lookup_var.get().strip()
        if not indicator:
            return

        def do_lookup():
            result = self.threatfox_client.lookup_ioc(indicator)

            def show():
                self.hide_progress()
                self._add_to_lookup_history(indicator, 'ThreatFox', result)
                self._show_threat_intel_result("ThreatFox", indicator, result)

            self.root.after(0, show)

        self.show_progress("Looking up on ThreatFox...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def _manual_abuseipdb_lookup(self):
        """Perform manual AbuseIPDB lookup (IP addresses only)"""
        indicator = self.manual_lookup_var.get().strip()
        if not indicator:
            return

        # AbuseIPDB only supports IP addresses
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            messagebox.showwarning("AbuseIPDB", "AbuseIPDB only supports IP address lookups")
            return

        def do_lookup():
            result = self.abuseipdb_client.lookup_ip(indicator)

            # Record to tracker for persistence
            if 'error' not in result:
                abuse_score = result.get('abuseConfidenceScore', 0)
                total_reports = result.get('totalReports', 0)
                if abuse_score >= 50 or total_reports >= 10:
                    status = 'DANGER'
                elif abuse_score >= 25 or total_reports >= 3:
                    status = 'suspect'
                else:
                    status = 'safe'
                details = {
                    'abuseConfidenceScore': abuse_score,
                    'totalReports': total_reports,
                    'countryCode': result.get('countryCode', ''),
                    'isp': result.get('isp', ''),
                }
                self.ip_tracker.record_lookup(indicator, status, source='AbuseIPDB', details=details)
            else:
                self.ip_tracker.record_lookup(indicator, 'error', source='AbuseIPDB',
                                              details={'error': result.get('error', 'Unknown')})

            def show():
                self.hide_progress()
                self._add_to_lookup_history(indicator, 'AbuseIPDB', result)
                self._show_threat_intel_result("AbuseIPDB", indicator, result)

            self.root.after(0, show)

        self.show_progress("Looking up on AbuseIPDB...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def create_general_settings_tab(self):
        """General application settings"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰒓 Cfg")

        # UI Settings
        ui_frame = ttk.LabelFrame(tab, text="󰋼 User Interface", padding="10")
        ui_frame.pack(fill=tk.X, pady=10)

        self.widgets.create_checkbox(ui_frame, text="Auto-refresh every 5 seconds",
                        variable=self.auto_refresh).pack(anchor=tk.W)

        refresh_row = ttk.Frame(ui_frame)
        refresh_row.pack(fill=tk.X, pady=5)
        ttk.Label(refresh_row, text="Refresh interval (seconds):").pack(side=tk.LEFT, padx=(0, 10))
        self.refresh_interval_var = tk.StringVar(value=str(self.refresh_interval // 1000))
        self.widgets.create_entry(refresh_row, textvariable=self.refresh_interval_var, width=8).pack(side=tk.LEFT)
        self.widgets.create_button(refresh_row, text="Apply", command=self.apply_refresh_interval).pack(side=tk.LEFT, padx=10)

        # Data retention setting
        retention_row = ttk.Frame(ui_frame)
        retention_row.pack(fill=tk.X, pady=5)
        ttk.Label(retention_row, text="Data retention (minutes):").pack(side=tk.LEFT, padx=(0, 10))
        self.data_retention_var = tk.StringVar(value=str(self.data_retention_minutes))
        retention_entry = self.widgets.create_entry(retention_row, textvariable=self.data_retention_var, width=8)
        retention_entry.pack(side=tk.LEFT)
        self.widgets.create_button(retention_row, text="Apply", command=self.apply_data_retention).pack(side=tk.LEFT, padx=10)
        ttk.Label(retention_row, text="(how long data stays in each tab)",
                 foreground=self.colors['gray']).pack(side=tk.LEFT, padx=5)

        # Notification Settings
        notif_frame = ttk.LabelFrame(tab, text="󰂞 Notifications", padding="10")
        notif_frame.pack(fill=tk.X, pady=10)

        self.desktop_notif_var = tk.BooleanVar(value=True)
        self.sound_alert_var = tk.BooleanVar(value=True)
        self.high_sev_only_var = tk.BooleanVar(value=False)

        self.widgets.create_checkbox(notif_frame, text="Desktop notifications for alerts",
                       variable=self.desktop_notif_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(notif_frame, text="Sound alerts for critical events",
                       variable=self.sound_alert_var).pack(anchor=tk.W)
        self.widgets.create_checkbox(notif_frame, text="Only notify for high severity (1-2)",
                       variable=self.high_sev_only_var).pack(anchor=tk.W)

        # Alert Monitor Services
        monitor_frame = ttk.LabelFrame(tab, text="󰂚 Alert Monitor Services", padding="10")
        monitor_frame.pack(fill=tk.X, pady=10)

        mon_btns = ttk.Frame(monitor_frame)
        mon_btns.pack(fill=tk.X)

        ttk.Label(mon_btns, text="Suricata Monitor:").pack(side=tk.LEFT, padx=(0, 10))
        self.widgets.create_button(mon_btns, text="Start", command=lambda: self.control_user_service('suricata-alerts', 'start')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(mon_btns, text="Stop", command=lambda: self.control_user_service('suricata-alerts', 'stop')).pack(side=tk.LEFT, padx=2)

        mon_btns2 = ttk.Frame(monitor_frame)
        mon_btns2.pack(fill=tk.X, pady=5)

        ttk.Label(mon_btns2, text="ClamAV Monitor:").pack(side=tk.LEFT, padx=(0, 10))
        self.widgets.create_button(mon_btns2, text="Start", command=lambda: self.control_user_service('clamav-alerts', 'start')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(mon_btns2, text="Stop", command=lambda: self.control_user_service('clamav-alerts', 'stop')).pack(side=tk.LEFT, padx=2)

        # System Actions
        system_frame = ttk.LabelFrame(tab, text="󰒓 System", padding="10")
        system_frame.pack(fill=tk.X, pady=10)

        sys_btns = ttk.Frame(system_frame)
        sys_btns.pack(fill=tk.X)
        self.widgets.create_button(sys_btns, text="󰑐 Refresh All Data", command=self.refresh_all).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(sys_btns, text="󰃢 Clean All Logs", command=self.clean_all_logs).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(sys_btns, text="󰈙 Open Log Directory", command=self.open_log_directory).pack(side=tk.LEFT, padx=2)

        # About & Roadmap
        about_frame = ttk.LabelFrame(tab, text="󰋼 About & Roadmap", padding="10")
        about_frame.pack(fill=tk.X, pady=10)

        ttk.Label(about_frame, text="Security Suite Control Panel v2.5",
                 font=('Hack Nerd Font', 11, 'bold')).pack(anchor=tk.W)
        ttk.Label(about_frame, text="Suricata/Snort IDS + ClamAV Antivirus + Threat Intelligence").pack(anchor=tk.W)

        self.widgets.create_button(about_frame, text="󰈙 View Roadmap", command=self.show_roadmap).pack(anchor=tk.W, pady=10)

    def run_command(self, cmd, sudo=False):
        """Execute command securely without shell=True.

        Args:
            cmd: Command as string or list. If string, will be split safely.
            sudo: If True, prepends pkexec to command.

        Returns:
            Command output as string.
        """
        try:
            # Convert string command to list if necessary
            if isinstance(cmd, str):
                cmd_list = cmd.split()
            else:
                cmd_list = list(cmd)

            if sudo:
                cmd_list = ["pkexec"] + cmd_list

            result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    # ==================== New Security Tabs ====================

    def create_connections_tab(self):
        """Active Network Connections tab - shows current connections via ss/netstat"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰖟 Conn")

        # Header with controls
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="󰖟 Active Network Connections", style='Title.TLabel').pack(side=tk.LEFT)

        # Filter controls
        self.widgets.create_label(header_frame, text="State:").pack(side=tk.LEFT, padx=(20, 5))
        self.conn_state_filter = tk.StringVar(value="all")
        state_combo = ttk.Combobox(header_frame, textvariable=self.conn_state_filter,
                                   values=["all", "ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT"],
                                   width=12, state='readonly')
        state_combo.pack(side=tk.LEFT, padx=(0, 10))
        state_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_connections())

        # Ungroup toggle (grouped by remote is default)
        self.conn_ungrouped = tk.BooleanVar(value=False)
        self.conn_ungroup_btn = self.widgets.create_button(
            header_frame, text="󰘷 Ungroup",
            command=self._toggle_conn_grouping
        )
        self.conn_ungroup_btn.pack(side=tk.LEFT, padx=(10, 5))

        self.widgets.create_button(header_frame, text="󰑐 Refresh", command=self.refresh_connections).pack(side=tk.RIGHT, padx=5)

        # Stats label
        self.conn_stats_label = ttk.Label(header_frame, text="", foreground=self.colors['cyan'])
        self.conn_stats_label.pack(side=tk.RIGHT, padx=10)

        # Connections Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('proto', 'local', 'remote', 'state', 'process', 'pid')
        self.conn_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', style='Alerts.Treeview')

        self.conn_tree.heading('proto', text='Proto', command=lambda: self.sort_connections('proto'))
        self.conn_tree.heading('local', text='Local Address', command=lambda: self.sort_connections('local'))
        self.conn_tree.heading('remote', text='Remote Address', command=lambda: self.sort_connections('remote'))
        self.conn_tree.heading('state', text='State', command=lambda: self.sort_connections('state'))
        self.conn_tree.heading('process', text='Process', command=lambda: self.sort_connections('process'))
        self.conn_tree.heading('pid', text='PID', command=lambda: self.sort_connections('pid'))

        self.conn_sort_column = 'state'
        self.conn_sort_reverse = False

        self.conn_tree.column('proto', width=60, anchor='center')
        self.conn_tree.column('local', width=180)
        self.conn_tree.column('remote', width=180)
        self.conn_tree.column('state', width=100, anchor='center')
        self.conn_tree.column('process', width=150)
        self.conn_tree.column('pid', width=60, anchor='center')

        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.conn_tree.xview)
        self.conn_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.conn_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Color tags
        self.conn_tree.tag_configure('established', foreground=self.colors['green'])
        self.conn_tree.tag_configure('listen', foreground=self.colors['cyan'])
        self.conn_tree.tag_configure('time_wait', foreground=self.colors['yellow'])

        self.connections_data = []

    def create_logs_tab(self):
        """System Logs Viewer tab - unified view of security-related logs"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰈙 Logs")

        # Header with controls
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="󰈙 System Security Logs", style='Title.TLabel').pack(side=tk.LEFT)

        # Log source selector
        self.widgets.create_label(header_frame, text="Source:").pack(side=tk.LEFT, padx=(20, 5))
        self.log_source_var = tk.StringVar(value="auth")
        source_combo = ttk.Combobox(header_frame, textvariable=self.log_source_var,
                                    values=["auth", "secure", "journal", "syslog", "messages"],
                                    width=12, state='readonly')
        source_combo.pack(side=tk.LEFT, padx=(0, 10))
        source_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_logs())

        # Lines to show
        self.widgets.create_label(header_frame, text="Lines:").pack(side=tk.LEFT, padx=(10, 5))
        self.log_lines_var = tk.StringVar(value="100")
        lines_combo = ttk.Combobox(header_frame, textvariable=self.log_lines_var,
                                   values=["50", "100", "200", "500"], width=6, state='readonly')
        lines_combo.pack(side=tk.LEFT)

        self.widgets.create_button(header_frame, text="󰑐 Refresh", command=self.refresh_logs).pack(side=tk.RIGHT, padx=5)

        # Filter entry
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        self.widgets.create_label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.log_filter_var = tk.StringVar()
        self.widgets.create_entry(filter_frame, textvariable=self.log_filter_var, width=40).pack(side=tk.LEFT)
        self.widgets.create_button(filter_frame, text="Apply", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)

        # Log text display (use tk.Text for tag support)
        log_text_frame = ttk.Frame(tab)
        log_text_frame.pack(fill=tk.BOTH, expand=True)

        self.logs_text = tk.Text(log_text_frame, height=25, bg=self.colors['bg_alt'],
                                 fg=self.colors['fg'], font=('Hack Nerd Font', 9),
                                 insertbackground=self.colors['fg'], wrap=tk.NONE)
        log_scroll_y = ttk.Scrollbar(log_text_frame, orient=tk.VERTICAL, command=self.logs_text.yview)
        log_scroll_x = ttk.Scrollbar(log_text_frame, orient=tk.HORIZONTAL, command=self.logs_text.xview)
        self.logs_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)

        self.logs_text.grid(row=0, column=0, sticky='nsew')
        log_scroll_y.grid(row=0, column=1, sticky='ns')
        log_scroll_x.grid(row=1, column=0, sticky='ew')
        log_text_frame.columnconfigure(0, weight=1)
        log_text_frame.rowconfigure(0, weight=1)

        # Color tags for log levels
        self.logs_text.tag_configure('error', foreground=self.colors['red'])
        self.logs_text.tag_configure('warning', foreground=self.colors['yellow'])
        self.logs_text.tag_configure('info', foreground=self.colors['cyan'])

    def create_firewall_tab(self):
        """Firewall Management tab - UFW/firewalld status and rules"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰒃 FW")

        # Header
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="󰒃 Firewall Status & Rules", style='Title.TLabel').pack(side=tk.LEFT)

        self.widgets.create_button(header_frame, text="󰑐 Refresh", command=self.refresh_firewall).pack(side=tk.RIGHT, padx=5)

        # Status frame
        status_frame = ttk.LabelFrame(tab, text="Firewall Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)

        self.fw_status_label = ttk.Label(status_frame, text="Checking firewall status...",
                                         font=('Hack Nerd Font', 11))
        self.fw_status_label.pack(anchor=tk.W)

        self.fw_type_label = ttk.Label(status_frame, text="", foreground=self.colors['gray'])
        self.fw_type_label.pack(anchor=tk.W)

        # Control buttons
        fw_btns = ttk.Frame(status_frame)
        fw_btns.pack(fill=tk.X, pady=10)
        self.widgets.create_button(fw_btns, text="󰐊 Enable", command=lambda: self._fw_control('enable')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(fw_btns, text="󰓛 Disable", command=lambda: self._fw_control('disable')).pack(side=tk.LEFT, padx=2)
        self.widgets.create_button(fw_btns, text="󰦛 Reset", command=lambda: self._fw_control('reset')).pack(side=tk.LEFT, padx=2)

        # Rules frame
        rules_frame = ttk.LabelFrame(tab, text="Active Rules", padding="10")
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.fw_rules_text = self.widgets.create_textbox(rules_frame, height=15, bg=self.colors['bg_alt'],
                                                         fg=self.colors['fg'], font=('Hack Nerd Font', 9),
                                                         insertbackground=self.colors['fg'])
        self.fw_rules_text.pack(fill=tk.BOTH, expand=True)

        # Quick rule addition
        quick_frame = ttk.LabelFrame(tab, text="Quick Rule", padding="10")
        quick_frame.pack(fill=tk.X, pady=5)

        quick_row = ttk.Frame(quick_frame)
        quick_row.pack(fill=tk.X)

        self.fw_action_var = tk.StringVar(value="allow")
        ttk.Radiobutton(quick_row, text="Allow", variable=self.fw_action_var, value="allow").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(quick_row, text="Deny", variable=self.fw_action_var, value="deny").pack(side=tk.LEFT, padx=5)

        ttk.Label(quick_row, text="Port:").pack(side=tk.LEFT, padx=(15, 5))
        self.fw_port_var = tk.StringVar()
        self.widgets.create_entry(quick_row, textvariable=self.fw_port_var, width=8).pack(side=tk.LEFT)

        ttk.Label(quick_row, text="Protocol:").pack(side=tk.LEFT, padx=(15, 5))
        self.fw_proto_var = tk.StringVar(value="tcp")
        proto_combo = ttk.Combobox(quick_row, textvariable=self.fw_proto_var,
                                   values=["tcp", "udp", "both"], width=6, state='readonly')
        proto_combo.pack(side=tk.LEFT)

        self.widgets.create_button(quick_row, text="Add Rule", command=self._add_fw_rule).pack(side=tk.LEFT, padx=15)

    def create_security_audit_tab(self):
        """Security Audit Checklist tab - system hardening assessment"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="󰒓 Audit")

        # Header
        header_frame = ttk.Frame(tab)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="󰒓 Security Audit & Hardening", style='Title.TLabel').pack(side=tk.LEFT)

        self.widgets.create_button(header_frame, text="󰑐 Run Audit", command=self.run_security_audit).pack(side=tk.RIGHT, padx=5)

        # Score display
        score_frame = ttk.Frame(tab)
        score_frame.pack(fill=tk.X, pady=10)

        self.audit_score_label = ttk.Label(score_frame, text="Security Score: --/100",
                                           font=('Hack Nerd Font', 14, 'bold'))
        self.audit_score_label.pack(side=tk.LEFT)

        self.audit_status_label = ttk.Label(score_frame, text="Run audit to check", foreground=self.colors['gray'])
        self.audit_status_label.pack(side=tk.LEFT, padx=20)

        # Create scrollable frame for audit items
        canvas = tk.Canvas(tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        self.audit_frame = ttk.Frame(canvas)

        self.audit_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.audit_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Define audit checks with detailed fix instructions
        self.audit_checks = [
            ('firewall', 'Firewall enabled', 'Enable firewall (ufw/firewalld)', {
                'description': 'A firewall controls incoming and outgoing network traffic based on security rules.',
                'file': '/etc/firewalld/firewalld.conf (Fedora) or /etc/ufw/ufw.conf (Ubuntu)',
                'commands': [
                    '# For Fedora/RHEL (firewalld):',
                    'sudo systemctl enable --now firewalld',
                    'sudo firewall-cmd --state',
                    '',
                    '# For Ubuntu/Debian (ufw):',
                    'sudo ufw enable',
                    'sudo ufw status verbose',
                ],
                'config': None
            }),
            ('ssh_root', 'SSH root login disabled', 'Edit /etc/ssh/sshd_config', {
                'description': 'Disabling root login via SSH prevents brute force attacks on the root account.',
                'file': '/etc/ssh/sshd_config',
                'commands': [
                    'sudo nano /etc/ssh/sshd_config',
                    'sudo systemctl restart sshd',
                ],
                'config': 'PermitRootLogin no'
            }),
            ('ssh_password', 'SSH password auth disabled', 'Use key-based auth', {
                'description': 'Key-based authentication is more secure than passwords and resistant to brute force.',
                'file': '/etc/ssh/sshd_config',
                'commands': [
                    '# First, ensure you have SSH keys set up:',
                    'ssh-keygen -t ed25519 -C "your_email@example.com"',
                    'ssh-copy-id user@host',
                    '',
                    '# Then disable password auth:',
                    'sudo nano /etc/ssh/sshd_config',
                    'sudo systemctl restart sshd',
                ],
                'config': 'PasswordAuthentication no\nPubkeyAuthentication yes'
            }),
            ('selinux', 'SELinux/AppArmor active', 'Enable mandatory access control', {
                'description': 'SELinux/AppArmor provides mandatory access control to limit damage from compromised processes.',
                'file': '/etc/selinux/config (Fedora) or /etc/apparmor.d/ (Ubuntu)',
                'commands': [
                    '# For Fedora/RHEL (SELinux):',
                    'sudo setenforce 1                    # Enable immediately',
                    'sudo nano /etc/selinux/config        # Set SELINUX=enforcing',
                    'getenforce                           # Verify status',
                    '',
                    '# For Ubuntu (AppArmor):',
                    'sudo systemctl enable --now apparmor',
                    'sudo aa-status',
                ],
                'config': 'SELINUX=enforcing'
            }),
            ('auto_updates', 'Automatic security updates', 'Enable dnf-automatic', {
                'description': 'Automatic updates ensure security patches are applied promptly.',
                'file': '/etc/dnf/automatic.conf (Fedora) or /etc/apt/apt.conf.d/50unattended-upgrades (Ubuntu)',
                'commands': [
                    '# For Fedora/RHEL:',
                    'sudo dnf install dnf-automatic',
                    'sudo systemctl enable --now dnf-automatic.timer',
                    '',
                    '# For Ubuntu/Debian:',
                    'sudo apt install unattended-upgrades',
                    'sudo dpkg-reconfigure -plow unattended-upgrades',
                ],
                'config': '[commands]\napply_updates = yes\nupgrade_type = security'
            }),
            ('fail2ban', 'Fail2ban running', 'Install and enable fail2ban', {
                'description': 'Fail2ban monitors logs and bans IPs showing malicious behavior (e.g., brute force).',
                'file': '/etc/fail2ban/jail.local',
                'commands': [
                    'sudo dnf install fail2ban           # Fedora',
                    'sudo apt install fail2ban           # Ubuntu',
                    'sudo systemctl enable --now fail2ban',
                    'sudo fail2ban-client status',
                ],
                'config': '[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 3600'
            }),
            ('disk_encrypt', 'Disk encryption enabled', 'Use LUKS encryption', {
                'description': 'Full disk encryption protects data if the physical drive is stolen.',
                'file': 'N/A - Must be configured during OS installation',
                'commands': [
                    '# Check if encryption is enabled:',
                    'lsblk -o NAME,TYPE,MOUNTPOINT,FSTYPE',
                    'sudo cryptsetup status /dev/mapper/luks-*',
                    '',
                    '# To encrypt a new drive:',
                    'sudo cryptsetup luksFormat /dev/sdX',
                    'sudo cryptsetup open /dev/sdX encrypted_drive',
                ],
                'config': '# Disk encryption must be set up during installation\n# or on unmounted partitions. Cannot be enabled live.'
            }),
            ('audit_log', 'Audit logging active', 'Enable auditd service', {
                'description': 'The audit daemon tracks security-relevant events for forensic analysis.',
                'file': '/etc/audit/auditd.conf',
                'commands': [
                    'sudo dnf install audit               # Fedora',
                    'sudo apt install auditd              # Ubuntu',
                    'sudo systemctl enable --now auditd',
                    'sudo auditctl -l                     # List rules',
                    'sudo ausearch -m LOGIN               # Search login events',
                ],
                'config': '# Add audit rules in /etc/audit/rules.d/audit.rules:\n-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/sudoers -p wa -k sudoers'
            }),
            ('sudo_nopasswd', 'No NOPASSWD sudo rules', 'Remove NOPASSWD from sudoers', {
                'description': 'NOPASSWD sudo rules allow privilege escalation without authentication.',
                'file': '/etc/sudoers and /etc/sudoers.d/*',
                'commands': [
                    '# Find NOPASSWD rules:',
                    'sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/',
                    '',
                    '# Edit sudoers safely:',
                    'sudo visudo',
                    'sudo visudo -f /etc/sudoers.d/filename',
                ],
                'config': '# Change:\n# user ALL=(ALL) NOPASSWD: ALL\n# To:\nuser ALL=(ALL) ALL'
            }),
            ('world_writable', 'No world-writable files', 'Fix file permissions', {
                'description': 'World-writable files can be modified by any user, posing a security risk.',
                'file': 'Various system files',
                'commands': [
                    '# Find world-writable files (excluding /proc, /sys):',
                    'sudo find / -xdev -type f -perm -0002 -ls 2>/dev/null',
                    '',
                    '# Find world-writable directories:',
                    'sudo find / -xdev -type d -perm -0002 -ls 2>/dev/null',
                    '',
                    '# Fix permissions:',
                    'sudo chmod o-w /path/to/file',
                ],
                'config': '# Remove world-write permission:\nchmod o-w filename\n\n# For directories that need sticky bit:\nchmod 1777 /tmp'
            }),
            ('suid_files', 'SUID files audited', 'Review setuid binaries', {
                'description': 'SUID binaries run with elevated privileges and can be exploited for privilege escalation.',
                'file': 'Various system binaries',
                'commands': [
                    '# Find all SUID files:',
                    'sudo find / -xdev -type f -perm -4000 -ls 2>/dev/null',
                    '',
                    '# Find all SGID files:',
                    'sudo find / -xdev -type f -perm -2000 -ls 2>/dev/null',
                    '',
                    '# Remove SUID if not needed:',
                    'sudo chmod u-s /path/to/binary',
                ],
                'config': '# Common legitimate SUID binaries:\n/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/su\n/usr/bin/mount\n/usr/bin/umount\n\n# Investigate any others!'
            }),
            ('kernel_params', 'Secure kernel params', 'Apply sysctl hardening', {
                'description': 'Kernel parameters can harden the system against network attacks and exploits.',
                'file': '/etc/sysctl.conf or /etc/sysctl.d/99-security.conf',
                'commands': [
                    '# Create security sysctl config:',
                    'sudo nano /etc/sysctl.d/99-security.conf',
                    '',
                    '# Apply changes:',
                    'sudo sysctl --system',
                    '',
                    '# Verify:',
                    'sysctl kernel.randomize_va_space',
                ],
                'config': '# Network hardening\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.tcp_syncookies = 1\n\n# Kernel hardening\nkernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nkernel.dmesg_restrict = 1'
            }),
        ]

        # Create expandable check items
        self.audit_labels = {}
        self.audit_details_frames = {}
        self.audit_expanded = {}

        for check_id, label, summary, details in self.audit_checks:
            # Main row (clickable header)
            row = ttk.Frame(self.audit_frame)
            row.pack(fill=tk.X, pady=2, padx=5)

            # Expand/collapse indicator
            expand_label = ttk.Label(row, text="▶", width=2, cursor="hand2")
            expand_label.pack(side=tk.LEFT)

            # Status icon
            status_label = ttk.Label(row, text="○", width=2)
            status_label.pack(side=tk.LEFT)

            # Check name
            name_label = ttk.Label(row, text=label, width=28, cursor="hand2")
            name_label.pack(side=tk.LEFT)

            # Brief fix hint
            fix_label = ttk.Label(row, text=summary, foreground=self.colors['gray'])
            fix_label.pack(side=tk.LEFT, padx=10)

            # Details frame (hidden by default)
            details_frame = ttk.Frame(self.audit_frame)
            details_frame.pack(fill=tk.X, pady=(0, 5), padx=(30, 10))
            details_frame.pack_forget()  # Hide initially

            # Details content
            desc_label = ttk.Label(details_frame, text=details['description'],
                                   wraplength=700, foreground=self.colors['fg'])
            desc_label.pack(anchor='w', pady=(5, 10))

            # File location
            file_frame = ttk.Frame(details_frame)
            file_frame.pack(fill=tk.X, pady=2)
            ttk.Label(file_frame, text="File:", foreground=self.colors['cyan'],
                     font=('Hack Nerd Font', 9, 'bold')).pack(side=tk.LEFT)
            ttk.Label(file_frame, text=f" {details['file']}",
                     foreground=self.colors['fg']).pack(side=tk.LEFT)

            # Commands
            if details['commands']:
                cmd_label = ttk.Label(details_frame, text="Commands:",
                                     foreground=self.colors['cyan'],
                                     font=('Hack Nerd Font', 9, 'bold'))
                cmd_label.pack(anchor='w', pady=(10, 2))

                cmd_text = tk.Text(details_frame, height=len(details['commands']),
                                  bg=self.colors['bg_alt'], fg=self.colors['green'],
                                  font=('Hack Nerd Font', 9), wrap=tk.NONE,
                                  insertbackground=self.colors['fg'])
                cmd_text.pack(fill=tk.X, pady=2)
                cmd_text.insert('1.0', '\n'.join(details['commands']))
                cmd_text.configure(state='disabled')

            # Config suggestion
            if details['config']:
                cfg_label = ttk.Label(details_frame, text="Configuration:",
                                     foreground=self.colors['cyan'],
                                     font=('Hack Nerd Font', 9, 'bold'))
                cfg_label.pack(anchor='w', pady=(10, 2))

                cfg_text = tk.Text(details_frame, height=min(8, details['config'].count('\n') + 1),
                                  bg=self.colors['bg_alt'], fg=self.colors['yellow'],
                                  font=('Hack Nerd Font', 9), wrap=tk.NONE,
                                  insertbackground=self.colors['fg'])
                cfg_text.pack(fill=tk.X, pady=2)
                cfg_text.insert('1.0', details['config'])
                cfg_text.configure(state='disabled')

            # Separator
            ttk.Separator(details_frame, orient='horizontal').pack(fill=tk.X, pady=10)

            # Store references
            self.audit_labels[check_id] = (status_label, fix_label)
            self.audit_details_frames[check_id] = details_frame
            self.audit_expanded[check_id] = False

            # Bind click events for expand/collapse
            def make_toggle(cid, exp_lbl, det_frm):
                def toggle(event=None):
                    if self.audit_expanded[cid]:
                        det_frm.pack_forget()
                        exp_lbl.configure(text="▶")
                        self.audit_expanded[cid] = False
                    else:
                        # Find the row and pack details after it
                        det_frm.pack(fill=tk.X, pady=(0, 5), padx=(30, 10),
                                    after=exp_lbl.master)
                        exp_lbl.configure(text="▼")
                        self.audit_expanded[cid] = True
                return toggle

            toggle_fn = make_toggle(check_id, expand_label, details_frame)
            expand_label.bind('<Button-1>', toggle_fn)
            name_label.bind('<Button-1>', toggle_fn)

    # ==================== New Tab Methods ====================

    def refresh_connections(self):
        """Refresh active network connections"""
        def do_refresh():
            try:
                # Use ss for modern socket statistics, fallback to netstat
                # Try ss first
                result = subprocess.run(
                    ["ss", "-tupn"],
                    capture_output=True, text=True, timeout=10
                )
                # If ss fails, try netstat
                if result.returncode != 0:
                    result = subprocess.run(
                        ["netstat", "-tupn"],
                        capture_output=True, text=True, timeout=10
                    )

                state_filter = self.conn_state_filter.get()
                connections = []
                states = {'ESTABLISHED': 0, 'LISTEN': 0, 'TIME_WAIT': 0, 'other': 0}

                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    proto = parts[0].upper()
                    state = parts[1] if len(parts) > 1 else ''

                    # Parse addresses
                    if 'ss' in result.args:
                        local = parts[4] if len(parts) > 4 else ''
                        remote = parts[5] if len(parts) > 5 else ''
                        proc = parts[-1] if 'users' in parts[-1] else ''
                    else:
                        local = parts[3] if len(parts) > 3 else ''
                        remote = parts[4] if len(parts) > 4 else ''
                        proc = parts[-1] if '/' in parts[-1] else ''

                    # Extract PID and process name
                    pid = ''
                    process = ''
                    if proc:
                        import re
                        pid_match = re.search(r'pid=(\d+)', proc) or re.search(r'(\d+)/', proc)
                        if pid_match:
                            pid = pid_match.group(1)
                        name_match = re.search(r'"([^"]+)"', proc) or re.search(r'/([^\s]+)', proc)
                        if name_match:
                            process = name_match.group(1)

                    # Count states
                    if state in states:
                        states[state] += 1
                    else:
                        states['other'] += 1

                    # Apply filter
                    if state_filter != 'all' and state != state_filter:
                        continue

                    connections.append({
                        'proto': proto,
                        'local': local,
                        'remote': remote,
                        'state': state,
                        'process': process,
                        'pid': pid
                    })

                # Sort
                sort_col = self.conn_sort_column
                connections.sort(key=lambda x: x.get(sort_col, ''), reverse=self.conn_sort_reverse)

                # Apply grouping unless ungrouped view is selected
                if not self.conn_ungrouped.get():
                    connections = self._group_connections_by_remote(connections)

                def update_ui():
                    # Build list of new values tuples for comparison
                    new_values = []
                    for conn in connections:
                        new_values.append((
                            conn['proto'], conn['local'], conn['remote'],
                            conn['state'], conn['process'], conn['pid']
                        ))

                    # Get current treeview values
                    current_items = self.conn_tree.get_children()
                    current_values = [self.conn_tree.item(item, 'values') for item in current_items]

                    # Update stats regardless (lightweight)
                    total = len(connections)
                    stats = f"{total} connections | EST: {states['ESTABLISHED']} | LISTEN: {states['LISTEN']}"
                    self.conn_stats_label.configure(text=stats)

                    # Compare - only update if data changed (silent refresh)
                    if new_values == current_values:
                        self.connections_data = connections
                        return

                    # Data changed - save scroll position and selection
                    scroll_pos = self.conn_tree.yview()
                    selected = self.conn_tree.selection()
                    selected_values = None
                    if selected:
                        try:
                            selected_values = self.conn_tree.item(selected[0], 'values')
                        except:
                            pass

                    # Clear and repopulate
                    for item in current_items:
                        self.conn_tree.delete(item)

                    self.connections_data = connections

                    for conn in connections:
                        state = conn['state'].lower()
                        tag = state if state in ['established', 'listen', 'time_wait'] else ''
                        self.conn_tree.insert('', tk.END, values=(
                            conn['proto'], conn['local'], conn['remote'],
                            conn['state'], conn['process'], conn['pid']
                        ), tags=(tag,) if tag else ())

                    # Restore scroll position
                    self.conn_tree.yview_moveto(scroll_pos[0])

                    # Restore selection if the same item still exists
                    if selected_values:
                        for item in self.conn_tree.get_children():
                            if self.conn_tree.item(item, 'values') == selected_values:
                                self.conn_tree.selection_set(item)
                                break

                self.root.after(0, update_ui)

            except Exception as e:
                print(f"Error refreshing connections: {e}")

        threading.Thread(target=do_refresh, daemon=True).start()

    def sort_connections(self, column):
        """Sort connections by column"""
        if self.conn_sort_column == column:
            self.conn_sort_reverse = not self.conn_sort_reverse
        else:
            self.conn_sort_column = column
            self.conn_sort_reverse = False
        self.refresh_connections()

    def _toggle_conn_grouping(self):
        """Toggle between grouped and ungrouped connections view"""
        current = self.conn_ungrouped.get()
        self.conn_ungrouped.set(not current)

        if self.conn_ungrouped.get():
            self.conn_ungroup_btn.configure(text="󰘸 Group")
        else:
            self.conn_ungroup_btn.configure(text="󰘷 Ungroup")

        self.refresh_connections()

    def _group_connections_by_remote(self, connections: list) -> list:
        """Group connections by remote address, appending x{count} for duplicates."""
        if not connections:
            return connections

        # Group by remote address
        remote_groups = {}
        for conn in connections:
            remote = conn.get('remote', '')
            if remote not in remote_groups:
                remote_groups[remote] = []
            remote_groups[remote].append(conn)

        # Build grouped result
        grouped = []
        for remote, group in remote_groups.items():
            # Use first entry as representative
            representative = group[0].copy()

            count = len(group)
            if count > 1:
                representative['remote'] = f"{remote} x{count}"
                representative['_group_count'] = count

            grouped.append(representative)

        return grouped

    def refresh_logs(self):
        """Refresh system logs display"""
        def do_refresh():
            try:
                source = self.log_source_var.get()
                lines = self.log_lines_var.get()
                filter_text = self.log_filter_var.get().strip()

                # Use journalctl for all sources (no sudo required, works on modern systemd systems)
                # Build command as list for safe execution
                if source == 'journal':
                    # All journal entries
                    cmd = ["journalctl", "-n", str(lines), "--no-pager"]
                elif source == 'auth':
                    # Authentication logs (sshd, sudo, login, etc.)
                    cmd = ["journalctl", "-n", str(lines), "--no-pager", "_COMM=sshd", "+", "_COMM=sudo", "+", "_COMM=login", "+", "_COMM=su", "+", "SYSLOG_FACILITY=10", "+", "SYSLOG_FACILITY=4"]
                elif source == 'secure':
                    # Security-related logs (auth + audit)
                    cmd = ["journalctl", "-n", str(lines), "--no-pager", "SYSLOG_FACILITY=10", "+", "SYSLOG_FACILITY=4", "+", "SYSLOG_FACILITY=13"]
                elif source == 'syslog':
                    # General syslog messages
                    cmd = ["journalctl", "-n", str(lines), "--no-pager", "-p", "info"]
                else:  # messages
                    # Kernel and system messages
                    cmd = ["journalctl", "-n", str(lines), "--no-pager", "-k", "+", "_TRANSPORT=kernel", "+", "SYSLOG_FACILITY=0"]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output = result.stdout if result.stdout else result.stderr

                # Apply grep filter in Python if specified (safer than shell piping)
                if filter_text:
                    filtered_lines = []
                    for line in output.split('\n'):
                        if filter_text.lower() in line.lower():
                            filtered_lines.append(line)
                    output = '\n'.join(filtered_lines)

                def update_ui():
                    self.logs_text.delete('1.0', tk.END)
                    for line in output.split('\n'):
                        line_lower = line.lower()
                        if 'error' in line_lower or 'failed' in line_lower or 'denied' in line_lower:
                            self.logs_text.insert(tk.END, line + '\n', 'error')
                        elif 'warning' in line_lower or 'warn' in line_lower:
                            self.logs_text.insert(tk.END, line + '\n', 'warning')
                        elif 'success' in line_lower or 'accepted' in line_lower:
                            self.logs_text.insert(tk.END, line + '\n', 'info')
                        else:
                            self.logs_text.insert(tk.END, line + '\n')

                self.root.after(0, update_ui)

            except Exception as e:
                self.root.after(0, lambda: self.logs_text.insert(tk.END, f"Error: {e}\n"))

        threading.Thread(target=do_refresh, daemon=True).start()

    def refresh_firewall(self):
        """Refresh firewall status and rules"""
        def do_refresh():
            try:
                fw_type = None
                status = "Unknown"
                rules = ""

                # Check for firewalld first (Fedora)
                result = subprocess.run(["systemctl", "is-active", "firewalld"],
                                       capture_output=True, text=True)
                if result.stdout.strip() == 'active':
                    fw_type = 'firewalld'
                    status = "✓ Active (firewalld)"
                    rules_result = subprocess.run(["firewall-cmd", "--list-all"],
                                                 capture_output=True, text=True)
                    rules = rules_result.stdout
                else:
                    # Check for UFW
                    result = subprocess.run(["ufw", "status"],
                                           capture_output=True, text=True)
                    if 'Status: active' in result.stdout:
                        fw_type = 'ufw'
                        status = "✓ Active (UFW)"
                        rules = result.stdout
                    elif 'Status: inactive' in result.stdout:
                        fw_type = 'ufw'
                        status = "✗ Inactive (UFW)"
                        rules = "Firewall is inactive"
                    else:
                        # Check iptables
                        result = subprocess.run(["iptables", "-L", "-n"],
                                               capture_output=True, text=True)
                        if result.stdout:
                            fw_type = 'iptables'
                            status = "? iptables (check manually)"
                            rules = result.stdout

                def update_ui():
                    color = self.colors['green'] if '✓' in status else self.colors['red']
                    self.fw_status_label.configure(text=status, foreground=color)
                    self.fw_type_label.configure(text=f"Detected: {fw_type or 'None'}")
                    self.fw_rules_text.delete('1.0', tk.END)
                    self.fw_rules_text.insert('1.0', rules if rules else "No rules found")

                self.root.after(0, update_ui)

            except Exception as e:
                self.root.after(0, lambda: self.fw_status_label.configure(text=f"Error: {e}"))

        threading.Thread(target=do_refresh, daemon=True).start()

    def _fw_control(self, action):
        """Control firewall (enable/disable/reset) with single auth prompt"""
        if action == 'reset' and not messagebox.askyesno("Confirm", "Reset firewall to defaults?"):
            return

        def do_action():
            # Detect firewall type
            result = subprocess.run(["which", "firewall-cmd"],
                                   capture_output=True, text=True)
            is_firewalld = result.returncode == 0

            if is_firewalld:
                if action == 'enable':
                    # Batch both commands with single auth
                    run_privileged_batch([
                        "systemctl start firewalld",
                        "systemctl enable firewalld",
                    ])
                elif action == 'disable':
                    run_privileged_batch(["systemctl stop firewalld"])
                else:  # reset
                    run_privileged_batch(["firewall-cmd --complete-reload"])
            else:
                if action == 'enable':
                    run_privileged_batch(["ufw --force enable"])
                elif action == 'disable':
                    run_privileged_batch(["ufw disable"])
                else:  # reset
                    run_privileged_batch(["ufw --force reset"])

            self.root.after(0, self.refresh_firewall)

        threading.Thread(target=do_action, daemon=True).start()

    def _add_fw_rule(self):
        """Add a firewall rule with input validation"""
        port = self.fw_port_var.get().strip()
        if not port:
            messagebox.showerror("Error", "Please enter a port number")
            return

        action = self.fw_action_var.get()
        proto = self.fw_proto_var.get()

        # Validate inputs
        valid, err = validate_port(port)
        if not valid:
            messagebox.showerror("Validation Error", err)
            return

        valid, err = validate_ufw_action(action)
        if not valid:
            messagebox.showerror("Validation Error", err)
            return

        if proto not in ['tcp', 'udp', 'both']:
            messagebox.showerror("Validation Error", "Invalid protocol")
            return

        def do_add():
            # Detect firewall type
            result = subprocess.run(["which", "firewall-cmd"],
                                   capture_output=True, text=True)
            is_firewalld = result.returncode == 0

            if is_firewalld:
                # Use run_privileged_batch for firewalld commands
                if proto == 'both':
                    commands = [
                        f"firewall-cmd --permanent --add-port={port}/tcp",
                        f"firewall-cmd --permanent --add-port={port}/udp",
                        "firewall-cmd --reload"
                    ]
                else:
                    commands = [
                        f"firewall-cmd --permanent --add-port={port}/{proto}",
                        "firewall-cmd --reload"
                    ]
                cmd_result = run_privileged_batch(commands)
                returncode = 0 if cmd_result.success else 1
                stderr = "" if cmd_result.success else cmd_result.message
            else:
                # UFW commands
                if proto == 'both':
                    commands = [
                        f"ufw {action} {port}/tcp",
                        f"ufw {action} {port}/udp"
                    ]
                    cmd_result = run_privileged_batch(commands)
                    returncode = 0 if cmd_result.success else 1
                    stderr = "" if cmd_result.success else cmd_result.message
                else:
                    result = subprocess.run(
                        ["pkexec", "ufw", action, f"{port}/{proto}"],
                        capture_output=True, text=True, timeout=30
                    )
                    returncode = result.returncode
                    stderr = result.stderr

            def show_result():
                if returncode == 0:
                    messagebox.showinfo("Success", f"Rule added: {action} {port}/{proto}")
                    self.refresh_firewall()
                else:
                    messagebox.showerror("Error", stderr or "Failed to add rule")

            self.root.after(0, show_result)

        threading.Thread(target=do_add, daemon=True).start()

    def run_security_audit(self):
        """Run security audit checks"""
        def do_audit():
            results = {}
            passed = 0
            total = len(self.audit_checks)  # Each check is (id, label, summary, details)

            # Check firewall - check firewalld first, then ufw
            fw_result = subprocess.run(["systemctl", "is-active", "firewalld"],
                                      capture_output=True)
            if fw_result.returncode != 0:
                # Try ufw
                ufw_result = subprocess.run(["ufw", "status"],
                                          capture_output=True, text=True)
                fw_result.returncode = 0 if 'Status: active' in ufw_result.stdout else 1
            results['firewall'] = fw_result.returncode == 0

            # Check SSH root login - test actual SSH behavior (no root needed)
            # Try to SSH as root - if root login is disabled, it will show Permission denied
            try:
                ssh_root_test = subprocess.run(
                    ["timeout", "2", "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=1",
                     "-o", "StrictHostKeyChecking=no", "root@localhost"],
                    capture_output=True, text=True, timeout=3
                )
                ssh_output = ssh_root_test.stderr + ssh_root_test.stdout
                results['ssh_root'] = 'Permission denied' in ssh_output
            except subprocess.TimeoutExpired:
                results['ssh_root'] = False  # Timeout means we couldn't determine

            # Check SSH password auth - test actual SSH behavior
            # If password auth is disabled, it won't be listed in the allowed auth methods
            try:
                ssh_pass_result = subprocess.run(
                    ["timeout", "2", "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=1",
                     "-o", "PreferredAuthentications=password", "localhost"],
                    capture_output=True, text=True, timeout=3
                )
                ssh_pass_output = ssh_pass_result.stderr + ssh_pass_result.stdout
                # Check if the error shows only non-password methods (publickey, gssapi, etc.)
                results['ssh_password'] = ('Permission denied' in ssh_pass_output and
                                           'password' not in ssh_pass_output.lower().split('Permission denied')[0])
            except subprocess.TimeoutExpired:
                results['ssh_password'] = False  # Timeout means we couldn't determine

            # Check SELinux/AppArmor
            # Try SELinux first
            selinux_result = subprocess.run(["getenforce"], capture_output=True, text=True)
            if selinux_result.returncode == 0 and selinux_result.stdout.strip() in ['Enforcing', 'Permissive']:
                results['selinux'] = True
            else:
                # Try AppArmor
                aa_result = subprocess.run(["aa-status", "--enabled"], capture_output=True)
                results['selinux'] = aa_result.returncode == 0

            # Check auto updates - check for timer (Fedora uses dnf-automatic.timer)
            # Try dnf-automatic.timer first
            auto_result = subprocess.run(["systemctl", "is-active", "dnf-automatic.timer"], capture_output=True)
            if auto_result.returncode != 0:
                # Try dnf-automatic
                auto_result = subprocess.run(["systemctl", "is-active", "dnf-automatic"], capture_output=True)
            if auto_result.returncode != 0:
                # Try unattended-upgrades (Ubuntu/Debian)
                auto_result = subprocess.run(["systemctl", "is-active", "unattended-upgrades"], capture_output=True)
            results['auto_updates'] = auto_result.returncode == 0

            # Check fail2ban
            f2b_result = subprocess.run(["systemctl", "is-active", "fail2ban"],
                                       capture_output=True)
            results['fail2ban'] = f2b_result.returncode == 0

            # Check disk encryption (simplified)
            luks_result = subprocess.run(["lsblk", "-o", "TYPE"],
                                        capture_output=True, text=True)
            results['disk_encrypt'] = 'crypt' in luks_result.stdout

            # Check audit logging
            audit_result = subprocess.run(["systemctl", "is-active", "auditd"],
                                         capture_output=True)
            results['audit_log'] = audit_result.returncode == 0

            # Check NOPASSWD sudo - test if sudo requires a password
            # Run a harmless command with sudo -n (non-interactive) - if it works, NOPASSWD is set
            nopasswd_result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True)
            # Pass if sudo -n fails (meaning password IS required)
            results['sudo_nopasswd'] = nopasswd_result.returncode != 0

            # World-writable files (quick check of common dirs)
            # Check /etc first
            ww_result = subprocess.run(
                ["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"],
                capture_output=True, text=True)
            if not ww_result.stdout.strip():
                # Also check /usr/local/bin
                ww_result = subprocess.run(
                    ["find", "/usr/local/bin", "-xdev", "-type", "f", "-perm", "-0002"],
                    capture_output=True, text=True)
            results['world_writable'] = len(ww_result.stdout.strip()) == 0

            # SUID files - check for unusual SUID files (pass if only standard ones)
            # This is informational - we'll pass it as it requires manual review
            results['suid_files'] = True

            # Kernel params
            sysctl_result = subprocess.run(["sysctl", "kernel.randomize_va_space"],
                                          capture_output=True, text=True)
            results['kernel_params'] = '= 2' in sysctl_result.stdout

            # Count passed
            passed = sum(1 for v in results.values() if v)
            score = int((passed / total) * 100)

            def update_ui():
                # Update score
                if score >= 80:
                    color = self.colors['green']
                    status = "Good security posture"
                elif score >= 50:
                    color = self.colors['yellow']
                    status = "Needs improvement"
                else:
                    color = self.colors['red']
                    status = "Significant vulnerabilities"

                self.audit_score_label.configure(text=f"Security Score: {score}/100", foreground=color)
                self.audit_status_label.configure(text=status, foreground=color)

                # Update individual checks
                for check_id, (status_label, fix_label) in self.audit_labels.items():
                    if results.get(check_id, False):
                        status_label.configure(text="✓", foreground=self.colors['green'])
                        fix_label.configure(foreground=self.colors['gray'])
                    else:
                        status_label.configure(text="✗", foreground=self.colors['red'])
                        fix_label.configure(foreground=self.colors['yellow'])

            self.root.after(0, update_ui)

        threading.Thread(target=do_audit, daemon=True).start()

    # ==================== Analytics Methods ====================

    def _set_stats_time_range(self, preset: str):
        """Set time range for stats/analytics and refresh"""
        self.stats_time_range.set(preset)

        # Update label text
        labels = {
            '1h': 'Last 1 hour',
            '6h': 'Last 6 hours',
            '24h': 'Last 24 hours',
            '7d': 'Last 7 days',
            '30d': 'Last 30 days'
        }
        self.stats_time_label.configure(text=f"Showing: {labels.get(preset, preset)}")

        # Update trends chart label
        if hasattr(self, 'trends_label_frame'):
            self.trends_label_frame.configure(text=f"󰄧 Alert Trends ({labels.get(preset, preset)})")

        self.refresh_analytics()

    def refresh_analytics(self):
        """Refresh all analytics charts with current data"""
        if not MATPLOTLIB_AVAILABLE:
            return

        def do_refresh():
            try:
                # Get time range from settings
                time_range = self.stats_time_range.get() if hasattr(self, 'stats_time_range') else '24h'

                # Calculate cutoff based on time range
                time_deltas = {
                    '1h': timedelta(hours=1),
                    '6h': timedelta(hours=6),
                    '24h': timedelta(hours=24),
                    '7d': timedelta(days=7),
                    '30d': timedelta(days=30)
                }
                delta = time_deltas.get(time_range, timedelta(hours=24))

                eve_file = self.get_active_eve_file()
                if not eve_file or not os.path.exists(eve_file):
                    self.root.after(0, lambda: self._show_analytics_error("EVE log file not found"))
                    return

                alerts_by_hour = defaultdict(int)
                protocols = defaultdict(int)
                source_ips = defaultdict(int)
                dest_ips = defaultdict(int)
                countries = defaultdict(int)

                cutoff = datetime.now() - delta
                cutoff_str = cutoff.strftime('%Y-%m-%dT%H:%M:%S')

                # Read last 10000 lines of EVE log (no root needed if file is readable)
                try:
                    # Validate file path
                    valid, err = validate_file_path(eve_file, must_exist=True,
                                                   allowed_dirs=["/var/log/suricata", "/var/log"])
                    if not valid:
                        raise ValueError(err)

                    # Try direct read first (faster, no auth needed)
                    result = subprocess.run(
                        ["tail", "-10000", eve_file],
                        capture_output=True, text=True, timeout=30
                    )

                    if result.returncode != 0 or not result.stdout:
                        # Fallback to pkexec if direct read fails
                        result = subprocess.run(
                            ["pkexec", "tail", "-10000", eve_file],
                            capture_output=True, text=True, timeout=30
                        )

                    lines_processed = 0
                    for line in result.stdout.split('\n'):
                        if not line.strip():
                            continue
                        try:
                            event = json.loads(line)
                            ts_str = event.get('timestamp', '')
                            if not ts_str:
                                continue

                            # Quick string comparison for cutoff (faster than parsing)
                            if ts_str[:19] < cutoff_str:
                                continue

                            lines_processed += 1
                            event_type = event.get('event_type', '')

                            # Count by time bucket for trend chart
                            # For short ranges (1h, 6h, 24h): group by hour of day
                            # For longer ranges (7d, 30d): group by date
                            if time_range in ['1h', '6h', '24h']:
                                time_key = ts_str[11:13] + ":00"  # Hour only
                            else:
                                time_key = ts_str[:10]  # Date only (YYYY-MM-DD)
                            alerts_by_hour[time_key] += 1

                            # Protocol distribution
                            proto = event.get('proto', '')
                            if proto:
                                protocols[proto] += 1

                            # Top external talkers (exclude private/local IPs)
                            src = event.get('src_ip', '')
                            dst = event.get('dest_ip', '')
                            if src and not is_private_ip(src):
                                source_ips[src] += 1
                            if dst and not is_private_ip(dst):
                                dest_ips[dst] += 1

                        except (json.JSONDecodeError, ValueError):
                            continue

                except Exception as e:
                    print(f"Error reading EVE: {e}")
                    self.root.after(0, lambda: self._show_analytics_error(f"Error reading log: {e}"))
                    return

                # Update charts on main thread
                def update_charts():
                    self._update_trends_chart(alerts_by_hour)
                    self._update_protocol_chart(protocols)
                    self._update_talkers_chart(source_ips, dest_ips)
                    if self.geo_text:
                        self._update_geo_display(countries, source_ips)

                self.root.after(0, update_charts)

            except Exception as e:
                print(f"Analytics refresh error: {e}")

        threading.Thread(target=do_refresh, daemon=True).start()

    def _show_analytics_error(self, message):
        """Show error message on analytics charts"""
        if hasattr(self, 'trends_ax'):
            self.trends_ax.clear()
            self.trends_ax.set_facecolor(self.colors['bg_alt'])
            self.trends_ax.text(0.5, 0.5, message, ha='center', va='center',
                               color=self.colors['red'], fontsize=10)
            self.trends_canvas.draw()

    def _update_trends_chart(self, alerts_by_time):
        """Update the alert trends chart"""
        self.trends_ax.clear()
        self.trends_ax.set_facecolor(self.colors['bg_alt'])

        time_range = self.stats_time_range.get() if hasattr(self, 'stats_time_range') else '24h'

        if time_range in ['1h', '6h', '24h']:
            # Hourly view - create 24 hour labels
            labels = [f"{h:02d}:00" for h in range(24)]
            counts = [alerts_by_time.get(label, 0) for label in labels]
            xlabel = 'Hour of Day'
            title = f'Events by Hour ({time_range})'
            skip_labels = 4  # Show every 4th label
        else:
            # Daily view - use actual dates from data
            if alerts_by_time:
                sorted_dates = sorted(alerts_by_time.keys())
                labels = sorted_dates
                counts = [alerts_by_time[d] for d in sorted_dates]
                # Format labels to show just month-day
                labels = [d[5:] for d in labels]  # MM-DD format
            else:
                labels = []
                counts = []
            xlabel = 'Date'
            title = f'Events by Day ({time_range})'
            skip_labels = max(1, len(labels) // 10)  # Show ~10 labels

        if not labels or not any(counts):
            self.trends_ax.text(0.5, 0.5, 'No data for selected time range',
                               ha='center', va='center', color=self.colors['gray'], fontsize=10)
        else:
            bars = self.trends_ax.bar(range(len(labels)), counts, color=self.colors['cyan'], alpha=0.7)

            # Highlight high activity
            max_count = max(counts) if counts else 0
            for bar, count in zip(bars, counts):
                if count > max_count * 0.8 and count > 0:
                    bar.set_color(self.colors['red'])

            self.trends_ax.set_xticks(range(len(labels)))
            self.trends_ax.set_xticklabels(labels)

            # Only show some labels to avoid crowding
            for i, label in enumerate(self.trends_ax.xaxis.get_ticklabels()):
                if i % skip_labels != 0:
                    label.set_visible(False)

        self.trends_ax.set_xlabel(xlabel, color=self.colors['fg'])
        self.trends_ax.set_ylabel('Events', color=self.colors['fg'])
        self.trends_ax.tick_params(colors=self.colors['fg'], rotation=45)
        self.trends_ax.set_title(title, color=self.colors['fg'])

        self.trends_figure.tight_layout()
        self.trends_canvas.draw()

    def _update_protocol_chart(self, protocols):
        """Update the protocol distribution pie chart"""
        self.proto_ax.clear()
        self.proto_ax.set_facecolor(self.colors['bg_alt'])

        if protocols:
            # Get top 6 protocols
            sorted_protos = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:6]
            labels = [p[0].upper() for p in sorted_protos]
            sizes = [p[1] for p in sorted_protos]

            colors = [self.colors['cyan'], self.colors['blue'], self.colors['purple'],
                     self.colors['yellow'], self.colors['orange'], self.colors['teal']]

            wedges, texts, autotexts = self.proto_ax.pie(
                sizes, labels=labels, autopct='%1.1f%%',
                colors=colors[:len(sizes)], textprops={'color': self.colors['fg']}
            )
            self.proto_ax.set_title('Protocol Distribution', color=self.colors['fg'])
        else:
            self.proto_ax.text(0.5, 0.5, 'No data', ha='center', va='center',
                              color=self.colors['gray'], fontsize=12)

        self.proto_figure.tight_layout()
        self.proto_canvas.draw()

    def _update_talkers_chart(self, source_ips, dest_ips):
        """Update the top external talkers chart (excludes private IPs)"""
        self.talkers_ax.clear()
        self.talkers_ax.set_facecolor(self.colors['bg_alt'])

        # Combine source and destination external IPs for a unified view
        combined_external = defaultdict(int)
        for ip, count in source_ips.items():
            combined_external[ip] += count
        for ip, count in dest_ips.items():
            combined_external[ip] += count

        if combined_external:
            # Get top 10 external IPs
            top_external = sorted(combined_external.items(), key=lambda x: x[1], reverse=True)[:10]
            ips = [ip[:15] + '...' if len(ip) > 15 else ip for ip, _ in top_external]
            counts = [count for _, count in top_external]

            y_pos = range(len(ips))
            self.talkers_ax.barh(y_pos, counts, color=self.colors['cyan'], alpha=0.7)
            self.talkers_ax.set_yticks(y_pos)
            self.talkers_ax.set_yticklabels(ips)
            self.talkers_ax.set_xlabel('Events', color=self.colors['fg'])
            self.talkers_ax.set_title('Top External IPs (excl. private)', color=self.colors['fg'])
            self.talkers_ax.tick_params(colors=self.colors['fg'])
            self.talkers_ax.invert_yaxis()
        else:
            self.talkers_ax.text(0.5, 0.5, 'No external IP data\n(all traffic is local)',
                                ha='center', va='center', color=self.colors['gray'], fontsize=10)

        self.talkers_figure.tight_layout()
        self.talkers_canvas.draw()

    def _update_geo_display(self, countries, source_ips):
        """Update the geographic distribution display"""
        if not self.geo_text:
            return

        self.geo_text.delete(1.0, tk.END)

        if not GEOIP_AVAILABLE:
            self.geo_text.insert(tk.END, "GeoIP not available. Install geoip2:\n")
            self.geo_text.insert(tk.END, "  pip install geoip2\n\n")
            self.geo_text.insert(tk.END, "And download MaxMind GeoLite2 database.")
            return

        self.geo_text.insert(tk.END, "Top Source IPs by Event Count:\n")
        self.geo_text.insert(tk.END, "=" * 50 + "\n\n")

        top_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:20]
        for ip, count in top_ips:
            self.geo_text.insert(tk.END, f"  {ip:20} - {count:5} events\n")

    # ==================== Suricata Settings Methods ====================

    def restart_ids(self):
        """Restart the Suricata IDS service"""
        def do_restart():
            result = subprocess.run(["pkexec", "systemctl", "restart", "suricata-laptop"],
                                   capture_output=True, text=True, timeout=30)
            self.root.after(100, self.refresh_status)
            if result.returncode == 0:
                self.root.after(100, lambda: messagebox.showinfo("Success", "IDS restarted successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error", f"Failed to restart IDS: {result.stderr}"))

        threading.Thread(target=do_restart, daemon=True).start()

    def load_suricata_settings(self):
        """Load current Suricata settings into the UI"""
        def do_load():
            try:
                # Get service status
                result = subprocess.run(
                    ["systemctl", "is-active", "suricata-laptop"],
                    capture_output=True, text=True, timeout=10
                )
                status = result.stdout.strip()
                status_text = f"Service Status: {status.upper()}"

                # Get uptime if running
                if status == "active":
                    result = subprocess.run(
                        ["systemctl", "show", "suricata-laptop", "--property=ActiveEnterTimestamp"],
                        capture_output=True, text=True, timeout=10
                    )
                    if 'ActiveEnterTimestamp=' in result.stdout:
                        ts = result.stdout.split('=')[1].strip()
                        status_text += f" (since {ts})"

                self.root.after(0, lambda: self.service_info.configure(text=status_text))

                # Get rule sources from suricata-update
                try:
                    result = subprocess.run(
                        ["suricata-update", "list-enabled-sources"],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        # Parse output - skip info lines, get enabled sources
                        lines = result.stdout.strip().split('\n')
                        sources_list = []
                        in_sources = False
                        for line in lines:
                            if 'Enabled sources:' in line:
                                in_sources = True
                                continue
                            if in_sources and line.strip().startswith('- '):
                                sources_list.append(line.strip()[2:])  # Remove "- " prefix
                        sources = "Enabled Sources:\n" + "\n".join(f"  - {s}" for s in sources_list) if sources_list else "No sources enabled"
                    else:
                        sources = "Unable to read rule sources"
                except Exception as e:
                    sources = f"Unable to read rule sources: {e}"

                def update_sources():
                    self.rule_sources_text.delete(1.0, tk.END)
                    self.rule_sources_text.insert(tk.END, sources)
                    # Also refresh the treeview
                    self._refresh_rule_sources()

                self.root.after(0, update_sources)

                # Detect network interfaces
                self.detect_interfaces()

                # Load current settings from suricata.yaml config file
                self._load_suricata_config_settings()

            except Exception as e:
                print(f"Error loading Suricata settings: {e}")

        threading.Thread(target=do_load, daemon=True).start()

    def _load_suricata_config_settings(self):
        """Load current settings from suricata.yaml for persistence display.

        Loads: interface, JA3/JA4, logging options, runmode, threads
        """
        try:
            # Read config file (doesn't need privilege for reading)
            config_path = "/etc/suricata/suricata.yaml"
            with open(config_path, 'r') as f:
                content = f.read()

            import re

            # Parse current interface from af-packet section
            current_iface = None
            iface_matches = re.findall(r'^\s*-\s*interface:\s*(\S+)', content, re.MULTILINE)
            for iface in iface_matches:
                if iface not in ('default', 'lo'):
                    current_iface = iface
                    break

            # Parse JA3/JA4 settings
            ja3_enabled = 'ja3-fingerprints: yes' in content
            ja4_enabled = 'ja4-fingerprints: yes' in content

            # Parse logging options from outputs section
            # Look for enabled: yes/no under each log type
            eve_enabled = bool(re.search(r'eve-log:.*?enabled:\s*yes', content, re.DOTALL))
            fast_enabled = bool(re.search(r'fast:.*?enabled:\s*yes', content, re.DOTALL))
            stats_enabled = bool(re.search(r'stats:.*?enabled:\s*yes', content, re.DOTALL))
            pcap_enabled = bool(re.search(r'pcap-log:.*?enabled:\s*yes', content, re.DOTALL))

            # Parse runmode
            runmode_match = re.search(r'^runmode:\s*(\S+)', content, re.MULTILINE)
            runmode = runmode_match.group(1) if runmode_match else 'autofp'

            # Parse detection threads (more complex - check detect-thread-ratio or threading settings)
            threads = 'auto'
            threads_match = re.search(r'detect-thread-ratio:\s*(\d+\.?\d*)', content)
            if threads_match:
                threads = threads_match.group(1)

            def update_ui():
                # Update interface status and dropdown
                if current_iface:
                    self.iface_status_label.configure(
                        text=f"Current config: {current_iface}",
                        foreground=self.colors['green']
                    )
                    self.iface_var.set(current_iface)
                else:
                    self.iface_status_label.configure(
                        text="Current config: not detected",
                        foreground=self.colors['yellow']
                    )

                # Update JA3/JA4 checkboxes and status
                self.ja3_enabled_var.set(ja3_enabled)
                self.ja4_enabled_var.set(ja4_enabled)

                status_parts = []
                if ja3_enabled:
                    status_parts.append("JA3: ✓")
                else:
                    status_parts.append("JA3: ✗")

                if ja4_enabled:
                    status_parts.append("JA4: ✓")
                else:
                    status_parts.append("JA4: ✗")

                status = " | ".join(status_parts)
                color = self.colors['green'] if (ja3_enabled or ja4_enabled) else self.colors['gray']
                self.ja_status_label.configure(text=f"Current status: {status}", foreground=color)

                # Update logging option checkboxes
                self.eve_json_var.set(eve_enabled)
                self.fast_log_var.set(fast_enabled)
                self.stats_log_var.set(stats_enabled)
                self.pcap_log_var.set(pcap_enabled)

                # Update runmode and threads
                if runmode in ('autofp', 'workers', 'single'):
                    self.runmode_var.set(runmode)
                self.thread_var.set(threads)

            self.root.after(0, update_ui)

        except PermissionError:
            # Fall back to pkexec method for reading config
            self.root.after(0, self._check_ja_status)
            self.root.after(0, lambda: self.iface_status_label.configure(
                text="Current config: requires privilege to read",
                foreground=self.colors['yellow']
            ))
        except Exception as e:
            print(f"Error loading suricata config settings: {e}")
            self.root.after(0, lambda: self.iface_status_label.configure(
                text=f"Current config: error reading",
                foreground=self.colors['red']
            ))

    def apply_ids_settings(self):
        """Apply IDS configuration changes and restart the service"""
        # Collect current settings from UI
        interface = self.iface_var.get()
        runmode = self.runmode_var.get()
        threads = self.thread_var.get()

        # Logging options
        eve_json = self.eve_json_var.get()
        fast_log = self.fast_log_var.get()
        stats_log = self.stats_log_var.get()
        pcap_log = self.pcap_log_var.get()

        # Build summary of changes
        changes = []
        changes.append(f"Interface: {interface}")
        changes.append(f"Run Mode: {runmode}")
        changes.append(f"Threads: {threads}")
        changes.append(f"EVE JSON: {'enabled' if eve_json else 'disabled'}")
        changes.append(f"Fast Log: {'enabled' if fast_log else 'disabled'}")
        changes.append(f"Stats Log: {'enabled' if stats_log else 'disabled'}")
        changes.append(f"PCAP Log: {'enabled' if pcap_log else 'disabled'}")

        # Ask for confirmation
        summary = "The following settings will be applied:\n\n" + "\n".join(changes)
        summary += "\n\nThis will restart the Suricata IDS service.\nContinue?"

        if not messagebox.askyesno("Apply IDS Settings", summary):
            return

        def do_apply():
            try:
                self.root.after(0, lambda: self.show_progress("Applying IDS settings..."))

                # Note: Full YAML editing would require a YAML library
                # For now, we handle the interface setting via systemd override
                # and show a message about manual config for other settings

                errors = []

                # Create/update systemd override for interface
                override_content = f"""[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i {interface} --pidfile /run/suricata.pid
"""
                # Write override to temp file, then copy with privilege
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
                    f.write(override_content)
                    temp_conf = f.name

                # Batch all commands with single auth prompt
                result = run_privileged_batch([
                    "mkdir -p /etc/systemd/system/suricata-laptop.service.d",
                    f"cp {temp_conf} /etc/systemd/system/suricata-laptop.service.d/interface.conf",
                    "chmod 644 /etc/systemd/system/suricata-laptop.service.d/interface.conf",
                    "systemctl daemon-reload",
                    "systemctl restart suricata-laptop",
                ])

                # Cleanup temp file
                try:
                    os.unlink(temp_conf)
                except OSError:
                    pass

                if not result.success:
                    errors.append(f"Failed to apply settings: {result.message}")

                def show_result():
                    self.hide_progress()
                    self.refresh_status()

                    if errors:
                        messagebox.showerror("Apply Failed",
                            "Some settings could not be applied:\n\n" + "\n".join(errors))
                    else:
                        msg = "IDS settings applied successfully!\n\n"
                        msg += f"Interface set to: {interface}\n\n"
                        msg += "Note: Logging and performance settings require manual editing of\n"
                        msg += "/etc/suricata/suricata.yaml (use 'Edit suricata.yaml' button)"
                        messagebox.showinfo("Success", msg)

                    self.ids_changes_label.configure(text="")

                self.root.after(0, show_result)

            except Exception as e:
                self.root.after(0, self.hide_progress)
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_apply, daemon=True).start()

    # Known rule sources with metadata
    RULE_SOURCES = {
        'et/open': {'vendor': 'Proofpoint', 'license': 'MIT', 'recommended': True, 'description': 'Emerging Threats Open'},
        'oisf/trafficid': {'vendor': 'OISF', 'license': 'MIT', 'recommended': True, 'description': 'Traffic ID rules'},
        'abuse.ch/feodotracker': {'vendor': 'abuse.ch', 'license': 'CC0', 'recommended': True, 'description': 'Botnet C2 IPs'},
        'abuse.ch/sslbl-blacklist': {'vendor': 'abuse.ch', 'license': 'CC0', 'recommended': True, 'description': 'Malicious SSL certs'},
        'abuse.ch/sslbl-ja3': {'vendor': 'abuse.ch', 'license': 'CC0', 'recommended': True, 'description': 'JA3 fingerprints'},
        'abuse.ch/urlhaus': {'vendor': 'abuse.ch', 'license': 'CC0', 'recommended': True, 'description': 'Malicious URLs'},
        'ptresearch/attackdetection': {'vendor': 'PT Research', 'license': 'Custom', 'recommended': True, 'description': '0-day detection'},
        'tgreen/hunting': {'vendor': 'tgreen', 'license': 'GPLv3', 'recommended': True, 'description': 'Threat hunting'},
        'etnetera/aggressive': {'vendor': 'Etnetera', 'license': 'MIT', 'recommended': False, 'description': 'Aggressive IP blacklist'},
        'malsilo/win-malware': {'vendor': 'malsilo', 'license': 'MIT', 'recommended': False, 'description': 'Windows malware'},
        'stamus/lateral': {'vendor': 'Stamus', 'license': 'GPL-3.0', 'recommended': False, 'description': 'Lateral movement'},
    }

    def _refresh_rule_sources(self):
        """Refresh the rule sources treeview with current status"""
        def do_refresh():
            try:
                # Get enabled sources
                result = subprocess.run(
                    ["suricata-update", "list-enabled-sources"],
                    capture_output=True, text=True, timeout=30
                )
                enabled_output = result.stdout if result.stdout else ""
                enabled_sources = set()

                for line in enabled_output.strip().split('\n'):
                    line = line.strip()
                    # Format is "  - source_name" - look for lines starting with "- "
                    if line.startswith('- '):
                        source_name = line[2:].strip()  # Remove "- " prefix
                        if source_name:
                            enabled_sources.add(source_name)

                # Update the treeview
                def update_tree():
                    # Clear existing items
                    for item in self.rule_sources_tree.get_children():
                        self.rule_sources_tree.delete(item)

                    # Build list for sorting
                    sources_list = []
                    for source, info in self.RULE_SOURCES.items():
                        status = "✓ Enabled" if source in enabled_sources else "○ Disabled"
                        rec_mark = " ★" if info['recommended'] else ""
                        sources_list.append({
                            'status': status,
                            'source': source + rec_mark,
                            'vendor': info['vendor'],
                            'license': info['license'],
                            'is_enabled': source in enabled_sources
                        })

                    # Sort by selected column
                    sort_col = self.rule_sources_sort_column
                    sources_list.sort(key=lambda x: x.get(sort_col, ''), reverse=self.rule_sources_sort_reverse)

                    # Add to treeview
                    for item in sources_list:
                        self.rule_sources_tree.insert('', tk.END, values=(
                            item['status'],
                            item['source'],
                            item['vendor'],
                            item['license']
                        ), tags=('enabled' if item['is_enabled'] else 'disabled',))

                    # Configure tag colors
                    self.rule_sources_tree.tag_configure('enabled', foreground=self.colors['green'])
                    self.rule_sources_tree.tag_configure('disabled', foreground=self.colors['gray'])

                self.root.after(0, update_tree)

            except Exception as e:
                error_msg = str(e)
                def show_error(msg=error_msg):
                    messagebox.showerror("Error", f"Failed to refresh sources: {msg}")
                self.root.after(0, show_error)

        threading.Thread(target=do_refresh, daemon=True).start()

    def sort_rule_sources(self, column):
        """Sort rule sources by column"""
        if self.rule_sources_sort_column == column:
            self.rule_sources_sort_reverse = not self.rule_sources_sort_reverse
        else:
            self.rule_sources_sort_column = column
            self.rule_sources_sort_reverse = False
        self._refresh_rule_sources()

    def _toggle_rule_source(self, event):
        """Toggle a rule source on/off when double-clicked"""
        selection = self.rule_sources_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.rule_sources_tree.item(item, 'values')
        if not values:
            return

        source_name = values[1].replace(' ★', '')  # Remove recommended marker
        is_enabled = values[0] == "✓ Enabled"

        if is_enabled:
            self._do_source_action(source_name, "disable-source", "Disabling")
        else:
            self._do_source_action(source_name, "enable-source", "Enabling")

    def _enable_selected_source(self):
        """Enable the selected rule source"""
        selection = self.rule_sources_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule source to enable")
            return

        item = selection[0]
        values = self.rule_sources_tree.item(item, 'values')
        if not values:
            return

        source_name = values[1].replace(' ★', '')  # Remove recommended marker

        if values[0] == "✓ Enabled":
            messagebox.showinfo("Already Enabled", f"{source_name} is already enabled")
            return

        self._do_source_action(source_name, "enable-source", "Enabling")

    def _disable_selected_source(self):
        """Disable the selected rule source"""
        selection = self.rule_sources_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule source to disable")
            return

        item = selection[0]
        values = self.rule_sources_tree.item(item, 'values')
        if not values:
            return

        source_name = values[1].replace(' ★', '')  # Remove recommended marker

        if values[0] == "○ Disabled":
            messagebox.showinfo("Already Disabled", f"{source_name} is already disabled")
            return

        self._do_source_action(source_name, "disable-source", "Disabling")

    def _do_source_action(self, source_name: str, action: str, action_desc: str):
        """Execute enable/disable action on a rule source"""
        def do_action():
            try:
                self.show_progress(f"{action_desc} {source_name}...")
                result = subprocess.run(
                    ["pkexec", "suricata-update", action, source_name],
                    capture_output=True, text=True, timeout=60
                )

                def show_result():
                    self.hide_progress()
                    if result.returncode == 0:
                        action_past = "enabled" if "enable" in action else "disabled"
                        messagebox.showinfo("Success", f"{source_name} has been {action_past}")
                        self._refresh_rule_sources()
                    else:
                        messagebox.showerror("Error", f"Failed: {result.stderr}")

                self.root.after(0, show_result)

            except Exception as e:
                error_msg = str(e)
                def show_error(msg=error_msg):
                    self.hide_progress()
                    messagebox.showerror("Error", msg)
                self.root.after(0, show_error)

        threading.Thread(target=do_action, daemon=True).start()

    def _enable_recommended_sources(self):
        """Enable all recommended rule sources"""
        recommended = [s for s, info in self.RULE_SOURCES.items() if info['recommended']]

        if not messagebox.askyesno("Enable Recommended Sources",
                                    f"This will enable {len(recommended)} recommended rule sources:\n\n" +
                                    "\n".join(f"  • {s}" for s in recommended) +
                                    "\n\nThis may take a few minutes. Continue?"):
            return

        def do_enable():
            self.show_progress("Enabling recommended sources...")
            errors = []

            for source in recommended:
                try:
                    result = subprocess.run(
                        ["pkexec", "suricata-update", "enable-source", source],
                        capture_output=True, text=True, timeout=60
                    )
                    if result.returncode != 0 and "already enabled" not in result.stderr.lower():
                        errors.append(f"{source}: {result.stderr}")
                except Exception as e:
                    errors.append(f"{source}: {str(e)}")

            def show_result():
                self.hide_progress()
                if errors:
                    messagebox.showwarning("Completed with errors",
                                           f"Some sources failed to enable:\n\n" + "\n".join(errors))
                else:
                    messagebox.showinfo("Success",
                                        "All recommended sources enabled!\n\n"
                                        "Click 'Update Rules' to download and apply the new rules.")
                self._refresh_rule_sources()

            self.root.after(0, show_result)

        threading.Thread(target=do_enable, daemon=True).start()

    def _check_ja_status(self):
        """Check current JA3/JA4 fingerprint status in suricata.yaml"""
        def do_check():
            try:
                result = subprocess.run(
                    ["pkexec", "cat", "/etc/suricata/suricata.yaml"],
                    capture_output=True, text=True, timeout=30
                )

                if result.returncode != 0:
                    def show_error():
                        self.ja_status_label.configure(
                            text="✗ Could not read config",
                            foreground=self.colors['red']
                        )
                    self.root.after(0, show_error)
                    return

                config = result.stdout

                # Check for JA3 setting
                ja3_enabled = False
                ja4_enabled = False

                # Look for ja3-fingerprints in app-layer.protocols.tls
                if 'ja3-fingerprints: yes' in config:
                    ja3_enabled = True
                if 'ja4-fingerprints: yes' in config:
                    ja4_enabled = True

                def update_ui():
                    self.ja3_enabled_var.set(ja3_enabled)
                    self.ja4_enabled_var.set(ja4_enabled)

                    status_parts = []
                    if ja3_enabled:
                        status_parts.append("JA3: ✓")
                    else:
                        status_parts.append("JA3: ✗")

                    if ja4_enabled:
                        status_parts.append("JA4: ✓")
                    else:
                        status_parts.append("JA4: ✗")

                    status = " | ".join(status_parts)
                    color = self.colors['green'] if (ja3_enabled or ja4_enabled) else self.colors['gray']

                    self.ja_status_label.configure(text=f"Current status: {status}", foreground=color)

                self.root.after(0, update_ui)

            except Exception as e:
                error_msg = str(e)
                def show_error(msg=error_msg):
                    self.ja_status_label.configure(
                        text=f"✗ Error: {msg}",
                        foreground=self.colors['red']
                    )
                self.root.after(0, show_error)

        threading.Thread(target=do_check, daemon=True).start()

    def _apply_ja_config(self):
        """Apply JA3/JA4 configuration changes to suricata.yaml"""
        ja3_enable = self.ja3_enabled_var.get()
        ja4_enable = self.ja4_enabled_var.get()

        def do_apply():
            try:
                self.show_progress("Updating JA3/JA4 configuration...")

                ja3_val = "yes" if ja3_enable else "no"
                ja4_val = "yes" if ja4_enable else "no"

                # Read the current config file
                config_path = "/etc/suricata/suricata.yaml"
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                except PermissionError:
                    # Try reading with sudo cat via subprocess
                    result = subprocess.run(
                        ["cat", config_path],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode != 0:
                        raise Exception(f"Cannot read config: {result.stderr}")
                    content = result.stdout

                # Update the settings using regex
                import re

                # Update JA3 setting
                content = re.sub(
                    r'(ja3-fingerprints:\s*)(yes|no)',
                    f'\\g<1>{ja3_val}',
                    content
                )

                # Update JA4 setting - if line exists, update it; otherwise add after JA3
                if re.search(r'ja4-fingerprints:\s*(yes|no)', content):
                    content = re.sub(
                        r'(ja4-fingerprints:\s*)(yes|no)',
                        f'\\g<1>{ja4_val}',
                        content
                    )
                else:
                    # JA4 line doesn't exist - add it after ja3-fingerprints line
                    content = re.sub(
                        r'(ja3-fingerprints:\s*(?:yes|no))',
                        f'\\g<1>\n      ja4-fingerprints: {ja4_val}',
                        content
                    )

                # Write to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    f.write(content)
                    temp_path = f.name

                # Use privileged commands to backup and copy
                commands = [
                    "cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak",
                    f"cp {temp_path} /etc/suricata/suricata.yaml",
                    "chmod 644 /etc/suricata/suricata.yaml",
                ]

                result = run_privileged_batch(commands)

                # Clean up temp file
                try:
                    os.unlink(temp_path)
                except:
                    pass

                def show_result():
                    self.hide_progress()
                    if result.success:
                        messagebox.showinfo("Success",
                            f"JA3/JA4 configuration updated!\n\n"
                            f"JA3: {'Enabled' if ja3_enable else 'Disabled'}\n"
                            f"JA4: {'Enabled' if ja4_enable else 'Disabled'}\n\n"
                            "Restart Suricata to apply changes.")
                        self._check_ja_status()
                    else:
                        messagebox.showerror("Error", f"Failed to update config:\n{result.message}")

                self.root.after(0, show_result)

            except Exception as e:
                error_msg = str(e)
                def show_error(msg=error_msg):
                    self.hide_progress()
                    messagebox.showerror("Error", msg)
                self.root.after(0, show_error)

        threading.Thread(target=do_apply, daemon=True).start()

    def edit_rule_sources(self):
        """Open the suricata-update sources configuration"""
        subprocess.Popen(["pkexec", "xdg-open", "/etc/suricata/update.yaml"])

    def view_enabled_rules(self):
        """Show enabled rule categories in a dialog"""
        def do_view():
            try:
                result = subprocess.run(
                    ["pkexec", "suricata-update", "list-sources"],
                    capture_output=True, text=True, timeout=30
                )
                output = result.stdout if result.stdout else "No sources configured"
            except Exception as e:
                output = f"Error: {str(e)}"

            def show_dialog():
                dialog = tk.Toplevel(self.root)
                dialog.title("Enabled Rule Sources")
                dialog.geometry("600x400")
                dialog.configure(bg=self.colors['bg'])

                text = self.widgets.create_textbox(dialog, bg=self.colors['bg_alt'],
                                                  fg=self.colors['fg'],
                                                  font=('Hack Nerd Font', 9))
                text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                text.insert(tk.END, output)
                text.configure(state='disabled')

                self.widgets.create_button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

            self.root.after(0, show_dialog)

        threading.Thread(target=do_view, daemon=True).start()

    def disable_rule_dialog(self):
        """Dialog to disable a specific rule by SID"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Disable Rule")
        dialog.geometry("400x200")
        dialog.configure(bg=self.colors['bg'])

        ttk.Label(dialog, text="Enter Rule SID to disable:").pack(pady=10)
        sid_var = tk.StringVar()
        self.widgets.create_entry(dialog, textvariable=sid_var, width=20).pack(pady=5)

        def do_disable():
            sid = sid_var.get().strip()
            if not sid.isdigit():
                messagebox.showerror("Error", "SID must be a number")
                return

            try:
                # Use privilege_helper for safe command execution (no shell injection)
                # Write SID to a temp file, then append to disable.conf
                import tempfile
                import shlex

                # Create temp file with the SID content
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sid', delete=False) as f:
                    f.write(f"{sid}\n")
                    temp_path = f.name

                try:
                    # Use run_privileged_batch for safe privileged execution
                    result = run_privileged_batch([
                        f"cat {shlex.quote(temp_path)} >> /etc/suricata/disable.conf"
                    ])
                    if result.success:
                        messagebox.showinfo("Success", f"Rule {sid} added to disable list.\nRun 'Update Rules' to apply.")
                        dialog.destroy()
                    else:
                        messagebox.showerror("Error", result.message)
                finally:
                    # Clean up temp file
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        self.widgets.create_button(dialog, text="Disable Rule", command=do_disable).pack(pady=10)
        self.widgets.create_button(dialog, text="Cancel", command=dialog.destroy).pack()

    def detect_interfaces(self):
        """Detect available network interfaces and populate dropdown"""
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=10
            )
            # Parse output in Python instead of using awk/grep
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and 'lo' not in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface and iface != 'lo':
                            interfaces.append(iface)
            if interfaces:
                self.iface_combo['values'] = interfaces
                # Only set a default if no interface is currently selected
                # (the actual configured interface will be loaded from config)
                current = self.iface_var.get()
                if not current or current not in interfaces:
                    # Try to pick a reasonable default (wifi or ethernet)
                    for iface in interfaces:
                        if iface.startswith('wl') or iface.startswith('en'):
                            self.iface_var.set(iface)
                            break
        except Exception as e:
            print(f"Error detecting interfaces: {e}")

    def test_suricata_config(self):
        """Test the Suricata configuration for errors"""
        def do_test():
            self.root.after(0, lambda: self.show_progress("Testing configuration..."))
            try:
                result = subprocess.run(
                    ["pkexec", "suricata", "-T", "-c", "/etc/suricata/suricata.yaml"],
                    capture_output=True, text=True, timeout=60
                )
                output = result.stdout + result.stderr

                def show_result():
                    self.hide_progress()
                    if "Configuration provided was successfully loaded" in output:
                        messagebox.showinfo("Config Test", "Configuration is valid!")
                    else:
                        # Show errors in dialog
                        dialog = tk.Toplevel(self.root)
                        dialog.title("Configuration Test Results")
                        dialog.geometry("700x400")
                        dialog.configure(bg=self.colors['bg'])

                        text = self.widgets.create_textbox(dialog, bg=self.colors['bg_alt'],
                                                          fg=self.colors['fg'],
                                                          font=('Hack Nerd Font', 9))
                        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                        text.insert(tk.END, output)
                        self.widgets.create_button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

                self.root.after(0, show_result)

            except Exception as e:
                self.root.after(0, self.hide_progress)
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_test, daemon=True).start()

    def reload_suricata_rules(self):
        """Reload Suricata rules without restart (using Unix socket)"""
        def do_reload():
            try:
                result = subprocess.run(
                    ["pkexec", "suricatasc", "-c", "reload-rules"],
                    capture_output=True, text=True, timeout=30
                )
                if "Success" in result.stdout or result.returncode == 0:
                    self.root.after(0, lambda: messagebox.showinfo("Success", "Rules reloaded successfully"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error",
                        f"Reload failed: {result.stderr or result.stdout}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_reload, daemon=True).start()

    # ==================== ClamAV Settings Methods ====================

    def control_clamav_service(self, service, action):
        """Control a ClamAV service (start/stop/restart)"""
        def do_control():
            # Validate service name and action
            valid, err = validate_service_name(service)
            if not valid:
                self.root.after(100, lambda: messagebox.showerror("Validation Error", err))
                return

            valid, err = validate_systemctl_action(action)
            if not valid:
                self.root.after(100, lambda: messagebox.showerror("Validation Error", err))
                return

            result = subprocess.run(
                ["pkexec", "systemctl", action, service],
                capture_output=True, text=True, timeout=30
            )
            # Refresh all status displays after service control
            self.root.after(100, self.refresh_status)
            self.root.after(200, self.load_clamav_settings)
            self.root.after(300, self.refresh_clamav_stats)  # Update top stats bar

            if result.returncode == 0:
                self.root.after(100, lambda: messagebox.showinfo("Success",
                    f"{service} {action}ed successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error",
                    f"Failed to {action} {service}: {result.stderr}"))

        threading.Thread(target=do_control, daemon=True).start()

    def load_clamav_settings(self):
        """Load current ClamAV settings into the UI.

        Uses the centralized service status cache for consistency across all tabs.
        """
        def do_load():
            try:
                # First refresh the centralized status cache (this also updates all UI)
                self.root.after(0, self.refresh_status)

                # Get signature info - iterate files in Python for safety
                try:
                    import glob
                    import os
                    sig_summary = []
                    total_sigs = 0

                    for pattern in ['/var/lib/clamav/*.cld', '/var/lib/clamav/*.cvd']:
                        for fpath in glob.glob(pattern):
                            fname = os.path.basename(fpath)
                            db_name = fname.split('.')[0]  # daily, main, bytecode
                            result = subprocess.run(
                                ["sigtool", "--info", fpath],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.stdout:
                                version = ""
                                sigs = 0
                                build_time = ""
                                for line in result.stdout.split('\n'):
                                    if line.startswith('Version:'):
                                        version = line.split(':')[1].strip()
                                    elif line.startswith('Signatures:'):
                                        sigs = int(line.split(':')[1].strip())
                                        total_sigs += sigs
                                    elif line.startswith('Build time:'):
                                        build_time = line.split(':', 1)[1].strip()
                                if version:
                                    sig_summary.append(f"{db_name}: v{version} ({sigs:,} sigs)")

                    if sig_summary:
                        sig_info = f"Total: {total_sigs:,} signatures | " + " | ".join(sig_summary)
                    else:
                        sig_info = "Unable to read signature info"
                except Exception as e:
                    sig_info = f"Unable to read signature info: {e}"

                self.root.after(0, lambda: self.sig_info_label.configure(text=sig_info))

            except Exception as e:
                print(f"Error loading ClamAV settings: {e}")

        threading.Thread(target=do_load, daemon=True).start()

    def apply_av_settings(self):
        """Apply ClamAV configuration changes and restart services"""
        # Collect current settings from UI
        onacc_enabled = self.onacc_enabled_var.get()
        onacc_persist = self.onacc_persist_var.get()
        freshclam_persist = self.freshclam_persist_var.get()
        move_to_quarantine = self.move_to_quarantine_var.get()
        quarantine_dir = self.quarantine_dir_var.get()
        update_freq = self.update_freq_var.get()

        # Scan options
        scan_recursive = self.scan_recursive_var.get()
        scan_archive = self.scan_archive_var.get()
        scan_ole2 = self.scan_ole2_var.get()
        scan_pdf = self.scan_pdf_var.get()
        scan_html = self.scan_html_var.get()
        scan_mail = self.scan_mail_var.get()
        heuristic = self.heuristic_var.get()

        max_filesize = self.max_filesize_var.get()
        max_scansize = self.max_scansize_var.get()

        # Get watch/exclude paths
        watch_paths = self.watch_paths_text.get(1.0, tk.END).strip()
        excl_paths = self.excl_paths_text.get(1.0, tk.END).strip()

        # Build summary of changes
        changes = []
        changes.append(f"On-Access Scanning (now): {'enabled' if onacc_enabled else 'disabled'}")
        changes.append(f"On-Access at boot: {'enabled' if onacc_persist else 'disabled'}")
        changes.append(f"Freshclam at boot: {'enabled' if freshclam_persist else 'disabled'}")
        changes.append(f"Move to Quarantine: {'yes' if move_to_quarantine else 'no'}")
        changes.append(f"Quarantine Dir: {quarantine_dir}")
        changes.append(f"Update Frequency: {update_freq} checks/day")
        changes.append(f"Scan Archives: {'yes' if scan_archive else 'no'}")
        changes.append(f"Heuristic Detection: {'yes' if heuristic else 'no'}")
        changes.append(f"Max File Size: {max_filesize}MB")

        # Ask for confirmation
        summary = "The following settings will be applied:\n\n" + "\n".join(changes)
        summary += "\n\nThis will restart ClamAV services.\nContinue?"

        if not messagebox.askyesno("Apply AV Settings", summary):
            return

        def do_apply():
            try:
                self.root.after(0, lambda: self.show_progress("Applying AV settings..."))

                errors = []
                messages = []

                # Detect system's ClamAV user/group (Fedora=clamupdate, Debian=clamav)
                clam_user, clam_group = get_clamav_user()

                # Build command batch for single auth prompt
                batch_commands = [
                    # Create quarantine directory (separate commands for validation)
                    f"mkdir -p {quarantine_dir}",
                    f"chown {clam_user}:{clam_group} {quarantine_dir}",
                ]

                # Service persistence settings (enable/disable for boot)
                if freshclam_persist:
                    batch_commands.append("systemctl enable clamav-freshclam")
                else:
                    batch_commands.append("systemctl disable clamav-freshclam")

                if onacc_persist:
                    batch_commands.append("systemctl enable clamav-clamonacc")
                else:
                    batch_commands.append("systemctl disable clamav-clamonacc")

                # Current session: start/stop on-access scanning
                if onacc_enabled:
                    batch_commands.append("systemctl start clamav-clamonacc")
                else:
                    batch_commands.append("systemctl stop clamav-clamonacc")

                # Always restart daemon and freshclam for current session
                batch_commands.append("systemctl restart clamav-daemon")
                batch_commands.append("systemctl restart clamav-freshclam")

                # Execute all with single auth prompt
                result = run_privileged_batch(batch_commands)

                if result.success:
                    messages.append(f"Quarantine directory: {quarantine_dir}")
                    messages.append(f"On-Access (now): {'started' if onacc_enabled else 'stopped'}")
                    messages.append(f"On-Access (boot): {'enabled' if onacc_persist else 'disabled'}")
                    messages.append(f"Freshclam (boot): {'enabled' if freshclam_persist else 'disabled'}")
                    messages.append("clamav-daemon restarted")
                    messages.append("clamav-freshclam restarted")
                else:
                    # Parse output to find which commands failed
                    if result.stdout:
                        for line in result.stdout.split('\n'):
                            if 'FAILED' in line:
                                errors.append(line.strip())
                    if result.stderr and result.stderr.strip():
                        errors.append(result.stderr.strip())
                    if not errors:
                        errors.append(f"Command batch failed (exit code {result.returncode})")

                def show_result():
                    self.hide_progress()
                    self.refresh_status()
                    self.load_clamav_settings()
                    self.refresh_clamav_stats()  # Update top stats bar

                    if errors:
                        messagebox.showerror("Apply Partially Failed",
                            "Some settings could not be applied:\n\n" + "\n".join(errors) +
                            "\n\nSuccessful:\n" + "\n".join(messages))
                    else:
                        msg = "AV settings applied successfully!\n\n"
                        msg += "\n".join(messages)
                        msg += "\n\nNote: Advanced scan options require manual editing of\n"
                        msg += "/etc/clamav/clamd.conf (use 'Edit clamd.conf' button)"
                        messagebox.showinfo("Success", msg)

                    self.av_changes_label.configure(text="")

                self.root.after(0, show_result)

            except Exception as e:
                self.root.after(0, self.hide_progress)
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_apply, daemon=True).start()

    def view_freshclam_log(self):
        """View the freshclam update log"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Freshclam Update Log")
        dialog.geometry("800x600")
        dialog.configure(bg=self.colors['bg'])

        text = self.widgets.create_textbox(dialog, bg=self.colors['bg_alt'],
                                          fg=self.colors['fg'],
                                          font=('Hack Nerd Font', 9))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        log_content = ""

        # Try journalctl first (Fedora/systemd)
        try:
            result = subprocess.run(
                ["journalctl", "-u", "clamav-freshclam", "--no-pager", "-n", "100"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout and result.stdout.strip():
                log_content = "=== Freshclam Service Log (journalctl) ===\n\n"
                log_content += result.stdout
        except Exception:
            pass

        # Also try the traditional log file location
        try:
            result = subprocess.run(
                ["tail", "-50", "/var/log/clamav/freshclam.log"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout:
                if log_content:
                    log_content += "\n\n=== Freshclam Log File ===\n\n"
                else:
                    log_content = "=== Freshclam Log File ===\n\n"
                log_content += result.stdout
        except Exception:
            pass

        # If still no content, run freshclam manually to show current status
        if not log_content or "-- No entries --" in log_content:
            try:
                text.insert(tk.END, "Checking current signature status...\n\n")
                text.update()
                result = subprocess.run(
                    ["freshclam", "--verbose"],
                    capture_output=True, text=True, timeout=60
                )
                log_content = "=== Current Signature Status ===\n\n"
                log_content += result.stdout if result.stdout else ""
                if result.stderr:
                    log_content += "\n" + result.stderr
            except subprocess.TimeoutExpired:
                log_content = "Freshclam update timed out (still running in background)"
            except Exception as e:
                log_content = f"Error running freshclam: {e}"

        if not log_content:
            log_content = "No freshclam log entries found.\n\n"
            log_content += "Tips:\n"
            log_content += "- The freshclam service may not be running\n"
            log_content += "- Use 'Update Now' button to trigger a manual update\n"
            log_content += "- Check 'journalctl -u clamav-freshclam' for service logs"

        text.delete(1.0, tk.END)
        text.insert(tk.END, log_content)
        text.configure(state='disabled')
        self.widgets.create_button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    def browse_quarantine_dir(self):
        """Browse for quarantine directory"""
        path = filedialog.askdirectory(initialdir="/var/lib/clamav")
        if path:
            self.quarantine_dir_var.set(path)

    def edit_clamd_conf(self):
        """Edit clamd.conf configuration file"""
        subprocess.Popen(["pkexec", "xdg-open", "/etc/clamav/clamd.conf"])

    def edit_freshclam_conf(self):
        """Edit freshclam.conf configuration file"""
        subprocess.Popen(["pkexec", "xdg-open", "/etc/clamav/freshclam.conf"])

    # ==================== Scheduled Scan Methods ====================

    def _apply_scheduled_scan(self):
        """Apply scheduled scan configuration via systemd timer"""
        if not self.scheduled_scan_enabled.get():
            messagebox.showwarning("Not Enabled", "Please enable scheduled scans first")
            return

        frequency = self.scan_frequency_var.get()
        scan_time = self.scan_time_var.get()
        day = self.scan_day_var.get()
        paths = self.scheduled_scan_paths.get("1.0", tk.END).strip()
        notify_desktop = self.scan_notify_desktop.get()
        notify_log = self.scan_notify_log.get()

        # Validate time format
        try:
            hour, minute = scan_time.split(':')
            int(hour), int(minute)
        except:
            messagebox.showerror("Invalid Time", "Please use HH:MM format for time")
            return

        if not paths:
            messagebox.showerror("No Paths", "Please specify at least one directory to scan")
            return

        # Build systemd OnCalendar string
        if frequency == 'daily':
            on_calendar = f"*-*-* {scan_time}:00"
        elif frequency == 'weekly':
            on_calendar = f"{day} *-*-* {scan_time}:00"
        else:  # monthly
            on_calendar = f"*-*-01 {scan_time}:00"

        # Build the scan command with notification
        paths_list = ' '.join(f'"{p.strip()}"' for p in paths.split('\n') if p.strip())
        quarantine_dir = self.quarantine_dir_var.get()

        notification_cmd = ""
        if notify_desktop:
            notification_cmd = ' && if [ "$FOUND" -gt 0 ]; then notify-send -u critical "ClamAV Scheduled Scan" "Found $FOUND threats. Check quarantine."; fi'

        scan_script = f'''#!/bin/bash
# ClamAV Scheduled Scan - Generated by Security Suite
LOG="/var/log/clamav/scheduled-scan.log"
QUARANTINE="{quarantine_dir}"
mkdir -p "$QUARANTINE"

echo "=== Scheduled Scan Started: $(date) ===" >> "$LOG"
FOUND=$(clamscan -r --move="$QUARANTINE" {paths_list} 2>&1 | tee -a "$LOG" | grep -c "FOUND$" || true)
echo "=== Scan Complete: $FOUND threats found ===" >> "$LOG"
{notification_cmd}
'''

        # Create timer content
        timer_content = f'''[Unit]
Description=ClamAV Scheduled Antivirus Scan Timer

[Timer]
OnCalendar={on_calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
'''

        # Create service content
        service_content = f'''[Unit]
Description=ClamAV Scheduled Antivirus Scan
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-scheduled-scan.sh
StandardOutput=journal
StandardError=journal
'''

        def do_apply():
            try:
                # Write script
                script_path = "/tmp/clamav-scheduled-scan.sh"
                with open(script_path, 'w') as f:
                    f.write(scan_script)

                # Write timer
                timer_path = "/tmp/clamav-scheduled-scan.timer"
                with open(timer_path, 'w') as f:
                    f.write(timer_content)

                # Write service
                service_path = "/tmp/clamav-scheduled-scan.service"
                with open(service_path, 'w') as f:
                    f.write(service_content)

                # Install with pkexec using run_privileged_batch
                install_commands = [
                    f"cp {script_path} /usr/local/bin/clamav-scheduled-scan.sh",
                    "chmod +x /usr/local/bin/clamav-scheduled-scan.sh",
                    f"cp {timer_path} /etc/systemd/system/clamav-scheduled-scan.timer",
                    f"cp {service_path} /etc/systemd/system/clamav-scheduled-scan.service",
                    "systemctl daemon-reload",
                    "systemctl enable clamav-scheduled-scan.timer",
                    "systemctl start clamav-scheduled-scan.timer"
                ]
                result = run_privileged_batch(install_commands)

                def show_result():
                    if result.success:
                        self.sched_scan_status.configure(
                            text=f"Status: Active ({frequency} at {scan_time})",
                            foreground=self.colors['green']
                        )
                        messagebox.showinfo("Success", "Scheduled scan configured and activated")
                    else:
                        messagebox.showerror("Error", f"Failed to configure: {result.message}")

                self.root.after(0, show_result)

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_apply, daemon=True).start()

    def _remove_scheduled_scan(self):
        """Remove scheduled scan configuration"""
        if not messagebox.askyesno("Confirm", "Remove scheduled scan configuration?"):
            return

        def do_remove():
            remove_commands = [
                "systemctl stop clamav-scheduled-scan.timer",
                "systemctl disable clamav-scheduled-scan.timer",
                "rm -f /etc/systemd/system/clamav-scheduled-scan.timer",
                "rm -f /etc/systemd/system/clamav-scheduled-scan.service",
                "rm -f /usr/local/bin/clamav-scheduled-scan.sh",
                "systemctl daemon-reload"
            ]
            result = run_privileged_batch(remove_commands)

            def show_result():
                self.scheduled_scan_enabled.set(False)
                self.sched_scan_status.configure(
                    text="Status: Not configured",
                    foreground=self.colors['gray']
                )
                if result.success:
                    messagebox.showinfo("Removed", "Scheduled scan configuration removed")
                else:
                    messagebox.showerror("Error", f"Failed to remove: {result.message}")

            self.root.after(0, show_result)

        threading.Thread(target=do_remove, daemon=True).start()

    def _check_scheduled_scan_status(self):
        """Check status of scheduled scan timer"""
        def do_check():
            result = subprocess.run(
                ["systemctl", "is-active", "clamav-scheduled-scan.timer"],
                capture_output=True, text=True, timeout=10
            )
            is_active = result.stdout.strip() == "active"

            # Get next run time if active
            next_run = ""
            if is_active:
                list_result = subprocess.run(
                    ["systemctl", "list-timers", "clamav-scheduled-scan.timer", "--no-pager"],
                    capture_output=True, text=True, timeout=10
                )
                if list_result.stdout:
                    # Find lines containing 'clamav'
                    for line in list_result.stdout.split('\n'):
                        if 'clamav' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                next_run = f" - Next: {parts[0]} {parts[1]}"
                            break

            def update_status():
                if is_active:
                    self.scheduled_scan_enabled.set(True)
                    self.sched_scan_status.configure(
                        text=f"Status: Active{next_run}",
                        foreground=self.colors['green']
                    )
                else:
                    self.sched_scan_status.configure(
                        text="Status: Not configured or inactive",
                        foreground=self.colors['gray']
                    )

            self.root.after(0, update_status)

        threading.Thread(target=do_check, daemon=True).start()

    # ==================== General Settings Methods ====================

    def apply_refresh_interval(self):
        """Apply the new refresh interval"""
        try:
            interval = int(self.refresh_interval_var.get())
            if interval < 1:
                raise ValueError("Interval must be at least 1 second")
            self.refresh_interval = interval * 1000  # Convert to milliseconds
            self.save_shared_settings()
            messagebox.showinfo("Success", f"Refresh interval set to {interval} seconds")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid interval: {e}")

    def apply_data_retention(self):
        """Apply the new data retention duration"""
        try:
            minutes = int(self.data_retention_var.get())
            if minutes < 1:
                raise ValueError("Retention must be at least 1 minute")
            self.data_retention_minutes = minutes
            # Clear caches to apply new retention immediately
            self.activity_cache = []
            self.traffic_cache = {'protocols': {}, 'http_hosts': {}, 'tls_hosts': {}, 'last_update': None}
            self.localhost_cache = {'port_activity': {}, 'events': [], 'last_update': None}
            self.dns_cache = {'queries': {}, 'query_types': {}, 'last_update': None}
            # Save to shared config for polybar sync
            self.save_shared_settings()
            messagebox.showinfo("Success", f"Data retention set to {minutes} minutes")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid retention value: {e}")

    def load_settings(self):
        """Load settings from config file on startup"""
        config_file = Path.home() / ".config" / "ids-suite" / "settings.conf"
        try:
            if config_file.exists():
                with open(config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            if key == 'retention_minutes':
                                self.data_retention_minutes = int(value)
                            elif key == 'refresh_interval':
                                self.refresh_interval = int(value) * 1000
                            elif key == 'auto_refresh':
                                # Will be applied after widgets created
                                self._saved_auto_refresh = value.lower() == 'true'
                print(f"Loaded settings: retention={self.data_retention_minutes}min, refresh={self.refresh_interval}ms")
        except Exception as e:
            print(f"Warning: Could not load settings: {e}")

        # Load persistent filters
        filters_file = Path.home() / ".config" / "ids-suite" / "filters.json"
        try:
            if filters_file.exists():
                with open(filters_file, 'r') as f:
                    filters = json.load(f)
                    self.hidden_signatures = set(filters.get('signatures', []))
                    self.hidden_src_ips = set(filters.get('src_ips', []))
                    self.hidden_dest_ips = set(filters.get('dest_ips', []))
                    self.hidden_categories = set(filters.get('categories', []))
                    total = len(self.hidden_signatures) + len(self.hidden_src_ips) + \
                            len(self.hidden_dest_ips) + len(self.hidden_categories)
                    if total > 0:
                        print(f"Loaded {total} persistent filters")
        except Exception as e:
            print(f"Warning: Could not load filters: {e}")

    def save_shared_settings(self):
        """Save settings to shared config file for polybar and other tools"""
        config_dir = Path.home() / ".config" / "ids-suite"
        config_file = config_dir / "settings.conf"
        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            with open(config_file, 'w') as f:
                f.write(f"retention_minutes={self.data_retention_minutes}\n")
                f.write(f"refresh_interval={self.refresh_interval // 1000}\n")
                f.write(f"auto_refresh={self.auto_refresh.get()}\n")
        except Exception as e:
            print(f"Warning: Could not save shared settings: {e}")

    def save_filters(self):
        """Save persistent filters to JSON file"""
        config_dir = Path.home() / ".config" / "ids-suite"
        filters_file = config_dir / "filters.json"
        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            filters = {
                'signatures': list(self.hidden_signatures),
                'src_ips': list(self.hidden_src_ips),
                'dest_ips': list(self.hidden_dest_ips),
                'categories': list(self.hidden_categories),
            }
            with open(filters_file, 'w') as f:
                json.dump(filters, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save filters: {e}")

    def purge_expired_cache_entries(self):
        """Remove entries older than the retention period from all caches"""
        cutoff = datetime.now() - timedelta(minutes=self.data_retention_minutes)

        # Purge activity cache
        self.activity_cache = [(ts, line) for ts, line in self.activity_cache if ts > cutoff]

        # Purge localhost events cache
        self.localhost_cache['events'] = [(ts, line) for ts, line in self.localhost_cache['events'] if ts > cutoff]

    def control_user_service(self, service, action):
        """Control a user-level systemd service"""
        def do_control():
            # Validate service name and action
            valid, err = validate_service_name(service)
            if not valid:
                self.root.after(0, lambda: messagebox.showerror("Validation Error", err))
                return

            valid, err = validate_systemctl_action(action)
            if not valid:
                self.root.after(0, lambda: messagebox.showerror("Validation Error", err))
                return

            result = subprocess.run(
                ["systemctl", "--user", action, service],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"{service} {action}ed"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error",
                    f"Failed: {result.stderr}"))

        threading.Thread(target=do_control, daemon=True).start()

    def clean_all_logs(self):
        """Clean all IDS and AV logs with single auth prompt"""
        if messagebox.askyesno("Confirm", "Clean all Suricata and ClamAV logs?"):
            def do_clean():
                # Single auth prompt for both cleanup scripts
                result = run_privileged_batch([
                    "/usr/local/bin/ids-cleanup",
                    "/usr/local/bin/av-cleanup",
                ])
                if result.success:
                    self.root.after(0, lambda: messagebox.showinfo("Success", "All logs cleaned"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Cleanup failed: {result.message}"))
                self.root.after(100, self.refresh_all)

            threading.Thread(target=do_clean, daemon=True).start()

    def open_log_directory(self):
        """Open file manager to log directories"""
        subprocess.Popen(["xdg-open", "/var/log/suricata/"])

    def show_roadmap(self):
        """Display the product roadmap with future plans"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Security Suite Roadmap")
        dialog.geometry("700x600")
        dialog.configure(bg=self.colors['bg'])

        # Create scrollable text
        text = self.widgets.create_textbox(dialog, bg=self.colors['bg_alt'],
                                          fg=self.colors['fg'],
                                          font=('Hack Nerd Font', 10),
                                          wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        roadmap = """
╔══════════════════════════════════════════════════════════════════╗
║           SECURITY SUITE CONTROL PANEL - ROADMAP                 ║
╚══════════════════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════════════
                         VERSION 2.0 (Current)
══════════════════════════════════════════════════════════════════

✓ Suricata IDS Integration
  - Service control (start/stop/restart)
  - Rule management and updates
  - Alert monitoring with Treeview
  - EVE JSON log parsing
  - Traffic, DNS, HTTP, TLS, and flow analysis
  - Alert filtering by severity, date, and text

✓ ClamAV Antivirus Integration
  - Service control for daemon, freshclam, on-access
  - Signature database management
  - Custom scanning with progress
  - Quarantine management (view, restore, delete)
  - Scan output with threat highlighting

✓ Analytics & Visualization
  - Alert trend charts (24-hour view)
  - Protocol distribution pie chart
  - Top talkers bar chart
  - GeoIP lookup support (optional)

✓ Core Features
  - Global search across tabs
  - Keyboard shortcuts (Ctrl+1-9, F5, Ctrl+F)
  - Data export (CSV/JSON)
  - Desktop notifications
  - Progress indicators
  - Comprehensive settings UI

══════════════════════════════════════════════════════════════════
                         VERSION 2.5 (Planned)
══════════════════════════════════════════════════════════════════

○ Snort IDS Integration
  - Add support for Snort 3 alongside Suricata
  - Unified alert view for both IDS engines
  - Snort rule management
  - Comparative analysis mode

○ Enhanced Threat Intelligence
  - Integration with OTX (Open Threat Exchange)
  - VirusTotal API lookup for suspicious IPs/hashes
  - Automated IOC extraction
  - Threat feed subscriptions

○ Network Flow Visualization
  - Interactive network topology graph
  - Connection flow diagrams
  - Traffic heatmaps
  - Real-time connection monitoring

══════════════════════════════════════════════════════════════════
                         VERSION 3.0 (Future)
══════════════════════════════════════════════════════════════════

○ Multi-System Management
  - Remote monitoring of multiple endpoints
  - Centralized alert dashboard
  - Agent-based architecture

○ SIEM Integration
  - Syslog forwarding
  - Elasticsearch/ELK stack integration
  - Splunk connector
  - Custom log shipping

○ Automated Response
  - Automated IP blocking (via iptables/nftables)
  - Quarantine automation rules
  - Custom response scripts
  - Alert escalation policies

○ Compliance Reporting
  - PCI-DSS compliance reports
  - HIPAA security reports
  - Custom report templates
  - Scheduled report generation

══════════════════════════════════════════════════════════════════
                       SNORT INTEGRATION DETAILS
══════════════════════════════════════════════════════════════════

Planned Snort 3 Features:
--------------------------
• Service control (start/stop/restart)
• Configuration management (snort.lua)
• Rule management (local.rules, community rules)
• Alert parsing (unified2, JSON output)
• Performance statistics
• Packet inspection modes (inline, passive)
• DAQ configuration
• Plugin management

Implementation Approach:
--------------------------
1. Detect if Snort is installed alongside Suricata
2. Add Snort-specific tab when detected
3. Support both engines running simultaneously
4. Unified alert format for comparison
5. Engine-agnostic statistics and trending

Configuration Notes:
--------------------------
• Snort 3 uses Lua configuration (snort.lua)
• Rules compatible with Suricata in most cases
• JSON logging for EVE-like output
• OpenAppID for application detection

══════════════════════════════════════════════════════════════════
                          CONTRIBUTING
══════════════════════════════════════════════════════════════════

This is an open project for personal security monitoring.
Feature requests and contributions are welcome!

For issues or suggestions, see the project repository.

══════════════════════════════════════════════════════════════════
"""

        text.insert(tk.END, roadmap)
        text.configure(state='disabled')

        self.widgets.create_button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    def get_active_eve_file(self):
        """Get the active EVE log file, handling log rotation.

        Returns the file with the most recent data. If eve.json is empty or missing,
        checks for rotated files like eve.json-YYYYMMDD.
        """
        eve_dir = "/var/log/suricata"
        primary_file = os.path.join(eve_dir, "eve.json")

        # Check if primary file exists and has data
        if os.path.exists(primary_file):
            try:
                size = os.path.getsize(primary_file)
                if size > 0:
                    return primary_file
            except OSError:
                pass

        # Look for rotated files (eve.json-YYYYMMDD format)
        try:
            rotated_files = []
            for f in os.listdir(eve_dir):
                if f.startswith("eve.json-") and os.path.isfile(os.path.join(eve_dir, f)):
                    fpath = os.path.join(eve_dir, f)
                    try:
                        mtime = os.path.getmtime(fpath)
                        size = os.path.getsize(fpath)
                        if size > 0:
                            rotated_files.append((fpath, mtime))
                    except OSError:
                        continue

            # Return most recently modified rotated file
            if rotated_files:
                rotated_files.sort(key=lambda x: x[1], reverse=True)
                return rotated_files[0][0]
        except OSError:
            pass

        # Fall back to primary file even if empty
        return primary_file

    # ========================================================================
    # CENTRALIZED SERVICE STATUS SYSTEM
    # All status checks should use these methods to ensure consistency
    # ========================================================================

    def _refresh_service_status_cache(self):
        """Refresh the centralized service status cache.

        This is the SINGLE function that queries systemctl for all services.
        All other status-related methods should read from the cache, not call
        systemctl directly. This ensures consistent status across all tabs.
        """
        services = ['suricata-laptop', 'clamav-daemon', 'clamav-freshclam', 'clamav-clamonacc']

        try:
            # Get active status for all services in one call
            result = subprocess.run(
                ["systemctl", "is-active"] + services,
                capture_output=True, text=True, timeout=5
            )
            active_statuses = result.stdout.strip().split('\n')

            # Get enabled status for all services in one call
            result_enabled = subprocess.run(
                ["systemctl", "is-enabled"] + services,
                capture_output=True, text=True, timeout=5
            )
            enabled_statuses = result_enabled.stdout.strip().split('\n')

            # Update cache with both active and enabled states
            self._service_status_cache['suricata'] = {
                'active': active_statuses[0] == 'active' if len(active_statuses) > 0 else False,
                'enabled': enabled_statuses[0] == 'enabled' if len(enabled_statuses) > 0 else False
            }
            self._service_status_cache['clamav_daemon'] = {
                'active': active_statuses[1] == 'active' if len(active_statuses) > 1 else False,
                'enabled': enabled_statuses[1] == 'enabled' if len(enabled_statuses) > 1 else False
            }
            self._service_status_cache['clamav_freshclam'] = {
                'active': active_statuses[2] == 'active' if len(active_statuses) > 2 else False,
                'enabled': enabled_statuses[2] == 'enabled' if len(enabled_statuses) > 2 else False
            }
            self._service_status_cache['clamav_clamonacc'] = {
                'active': active_statuses[3] == 'active' if len(active_statuses) > 3 else False,
                'enabled': enabled_statuses[3] == 'enabled' if len(enabled_statuses) > 3 else False
            }
            self._service_status_cache['last_update'] = datetime.now()

        except Exception as e:
            print(f"Error refreshing service status cache: {e}")
            # Keep existing cache values on error

    def get_all_service_status(self):
        """Get all service statuses from cache (for backwards compatibility).

        Returns dict with 'active' status for each service.
        """
        return {
            'suricata': self._service_status_cache['suricata']['active'],
            'clamav_daemon': self._service_status_cache['clamav_daemon']['active'],
            'clamav_freshclam': self._service_status_cache['clamav_freshclam']['active'],
            'clamav_clamonacc': self._service_status_cache['clamav_clamonacc']['active'],
        }

    def is_running(self):
        """Check if Suricata is running (from cache)."""
        return self._service_status_cache['suricata']['active']

    def is_clamav_running(self):
        """Check if ClamAV daemon is running (from cache)."""
        return self._service_status_cache['clamav_daemon']['active']

    def is_freshclam_running(self):
        """Check if Freshclam is running (from cache)."""
        return self._service_status_cache['clamav_freshclam']['active']

    def is_clamonacc_running(self):
        """Check if ClamAV on-access scanner is running (from cache)."""
        return self._service_status_cache['clamav_clamonacc']['active']

    def is_suricata_enabled(self):
        """Check if Suricata is enabled at boot (from cache)."""
        return self._service_status_cache['suricata']['enabled']

    def is_freshclam_enabled(self):
        """Check if Freshclam is enabled at boot (from cache)."""
        return self._service_status_cache['clamav_freshclam']['enabled']

    def is_clamonacc_enabled(self):
        """Check if ClamAV on-access is enabled at boot (from cache)."""
        return self._service_status_cache['clamav_clamonacc']['enabled']

    def refresh_status(self):
        """Refresh all service statuses and update ALL UI components.

        This is the SINGLE function that should be called when service status
        changes. It updates the cache and then updates all UI elements.
        """
        # First, refresh the cache
        self._refresh_service_status_cache()

        # Now update all UI components using the cache
        statuses = self.get_all_service_status()

        # === TOP BAR: Suricata status icon and buttons ===
        if statuses['suricata']:
            self.status_icon.configure(fg=self.colors['green'])
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
        else:
            self.status_icon.configure(fg=self.colors['red'])
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')

        # === TOP BAR: ClamAV daemon status icon and buttons ===
        if statuses['clamav_daemon']:
            self.clamav_status_icon.configure(fg=self.colors['green'])
            self.clamav_start_btn.configure(state='disabled')
            self.clamav_stop_btn.configure(state='normal')
        else:
            self.clamav_status_icon.configure(fg=self.colors['red'])
            self.clamav_start_btn.configure(state='normal')
            self.clamav_stop_btn.configure(state='disabled')

        # === AV CONFIG TAB: Service info text and persistence checkboxes ===
        try:
            # Service status text line
            status_parts = []
            status_parts.append(f"clamav-daemon: {'ACTIVE' if statuses['clamav_daemon'] else 'INACTIVE'}")
            status_parts.append(f"clamav-freshclam: {'ACTIVE' if statuses['clamav_freshclam'] else 'INACTIVE'}")
            status_parts.append(f"clamav-clamonacc: {'ACTIVE' if statuses['clamav_clamonacc'] else 'INACTIVE'}")
            self.clamav_service_info.configure(text=" | ".join(status_parts))

            # Persistence checkboxes - sync with cache
            self.freshclam_persist_var.set(self.is_freshclam_enabled())
            self.onacc_persist_var.set(self.is_clamonacc_enabled())
            self.onacc_enabled_var.set(statuses['clamav_clamonacc'])

            # Persistence status labels
            fc_enabled = self.is_freshclam_enabled()
            fc_status = "✓ Enabled at boot" if fc_enabled else "○ Disabled at boot"
            fc_color = self.colors['green'] if fc_enabled else self.colors['gray']
            self.freshclam_persist_status.configure(text=f"Freshclam: {fc_status}", foreground=fc_color)

            oa_enabled = self.is_clamonacc_enabled()
            oa_status = "✓ Enabled at boot" if oa_enabled else "○ Disabled at boot"
            oa_color = self.colors['green'] if oa_enabled else self.colors['gray']
            self.onacc_persist_status.configure(text=f"On-Access: {oa_status}", foreground=oa_color)

        except AttributeError:
            # Widgets may not exist yet during initial load
            pass

        # === CLAMAV DASHBOARD: Stats bar (daemon, freshclam, onaccess) ===
        try:
            self.clamav_stat_widgets['daemon'].configure(
                text="ON" if statuses['clamav_daemon'] else "OFF",
                fg=self.colors['green'] if statuses['clamav_daemon'] else self.colors['red']
            )
            self.clamav_stat_widgets['freshclam'].configure(
                text="ON" if statuses['clamav_freshclam'] else "OFF",
                fg=self.colors['green'] if statuses['clamav_freshclam'] else self.colors['red']
            )
            self.clamav_stat_widgets['onaccess'].configure(
                text="ON" if statuses['clamav_clamonacc'] else "OFF",
                fg=self.colors['green'] if statuses['clamav_clamonacc'] else self.colors['yellow']
            )
        except AttributeError:
            # Widgets may not exist yet during initial load
            pass

    def _update_eve_buffer(self):
        """Read new EVE lines and update the shared event buffer.

        All refresh functions should call this first to ensure data is current.
        Uses incremental reading with rotation detection.
        """
        try:
            # Read new lines using incremental reader
            if not self.eve_initial_load_done:
                lines = self.eve_reader.initial_load(10000)
                self.eve_initial_load_done = True
            else:
                lines = self.eve_reader.read_new_lines(5000)

            # Parse all events and add to buffer (store raw JSON dict)
            for line in lines:
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    timestamp = data.get('timestamp', '')[:19]
                    self.eve_event_buffer.append({
                        'timestamp': timestamp,
                        'data': data  # Full parsed JSON
                    })
                except json.JSONDecodeError:
                    continue

            # Prune buffer by retention
            retention_cutoff = datetime.now() - timedelta(minutes=self.data_retention_minutes)
            cutoff_str = retention_cutoff.strftime('%Y-%m-%dT%H:%M:%S')
            self.eve_event_buffer = [
                e for e in self.eve_event_buffer
                if e['timestamp'] >= cutoff_str
            ]

            self.eve_buffer_last_update = datetime.now()

        except Exception as e:
            print(f"Error updating EVE buffer: {e}")

    def refresh_stats(self):
        """Refresh stats from shared EVE buffer"""
        # Update the shared buffer first
        self._update_eve_buffer()

        counts = {'alerts': 0, 'http': 0, 'dns': 0, 'tls': 0, 'ssh': 0, 'localhost': 0}

        # Count from buffer
        for entry in self.eve_event_buffer:
            data = entry['data']
            event_type = data.get('event_type', '')
            src_ip = data.get('src_ip', '')

            if event_type == 'alert':
                counts['alerts'] += 1
            elif event_type == 'http':
                counts['http'] += 1
            elif event_type == 'dns':
                counts['dns'] += 1
            elif event_type == 'tls':
                counts['tls'] += 1
            elif event_type == 'ssh':
                counts['ssh'] += 1

            if src_ip and src_ip.startswith('127.'):
                counts['localhost'] += 1

        for key, count in counts.items():
            if key in self.stat_widgets:
                self.stat_widgets[key].configure(text=str(count))

    def refresh_activity(self):
        """Refresh activity feed from shared EVE buffer"""
        # Update the shared buffer first
        self._update_eve_buffer()

        # Purge expired entries first
        self.purge_expired_cache_entries()

        # Build set of existing display lines to avoid duplicates
        existing_lines = {line for _, line in self.activity_cache}
        new_entries = []
        now = datetime.now()

        # Process events from buffer (most recent ones)
        for entry in self.eve_event_buffer[-100:]:  # Last 100 events for activity
            data = entry['data']
            ts = entry['timestamp']
            event = data.get('event_type', 'unknown')
            src = data.get('src_ip', 'N/A')
            dst = data.get('dest_ip', 'N/A')

            display_line = None
            if event == 'alert':
                sig = data.get('alert', {}).get('signature', 'Unknown')
                display_line = f"[{ts}] 󰀦 ALERT: {sig}"
            elif event == 'http':
                host = data.get('http', {}).get('hostname', 'N/A')
                display_line = f"[{ts}] 󰖟 HTTP: {src} → {host}"
            elif event == 'dns':
                query = data.get('dns', {}).get('rrname', 'N/A')
                display_line = f"[{ts}] 󰇖 DNS: {query}"
            elif event == 'tls':
                sni = data.get('tls', {}).get('sni', 'N/A')
                display_line = f"[{ts}] 󰌆 TLS: {src} → {sni}"
            elif event == 'ssh':
                display_line = f"[{ts}] 󰣀 SSH: {src} → {dst}"

            if display_line and display_line not in existing_lines:
                new_entries.append((now, display_line))
                existing_lines.add(display_line)

        # Prepend new entries to cache (newest first)
        self.activity_cache = new_entries + self.activity_cache

        # Limit cache size to prevent memory issues (keep last 200 entries max)
        self.activity_cache = self.activity_cache[:200]

        # Update the display - newest entries at top
        self.activity_text.delete(1.0, tk.END)
        for _, display_line in self.activity_cache:
            self.activity_text.insert(tk.END, f"{display_line}\n")

    def refresh_alerts(self):
        """Refresh alerts using shared EVE buffer (silent refresh)"""
        # If in historical mode, use historical refresh instead
        if self.historical_mode:
            return self._refresh_historical_alerts()

        # Update the shared buffer first
        self._update_eve_buffer()

        severity_filter = self.severity_var.get()
        date_from = self.date_from_var.get().strip()
        date_to = self.date_to_var.get().strip()
        engine_filter = self.engine_filter.get().lower()

        # Build display data from buffer - filter for alert events only
        new_alerts_data = []
        for entry in self.eve_event_buffer:
            data = entry['data']
            timestamp = entry['timestamp']

            # Only process alert events
            if data.get('event_type') != 'alert':
                continue

            alert_data = data.get('alert', {})
            severity = alert_data.get('severity', 3)

            # Engine filter (Suricata is the source for EVE logs)
            if engine_filter != "all" and engine_filter != "suricata":
                continue

            # Severity filter
            if severity_filter != "all":
                filter_sev = int(severity_filter[0])
                if severity != filter_sev:
                    continue

            # Date range filter
            if date_from and timestamp[:10] < date_from:
                continue
            if date_to and timestamp[:10] > date_to:
                continue

            src_ip = data.get('src_ip', 'N/A')
            dst_ip = data.get('dest_ip', 'N/A')
            src_port = data.get('src_port', '')
            dst_port = data.get('dest_port', '')
            alert_entry = {
                'timestamp': timestamp,
                'severity': severity,
                'engine': 'Suricata',
                'signature': alert_data.get('signature', 'Unknown'),
                'category': alert_data.get('category', 'Unknown'),
                'source': f"{src_ip}:{src_port}" if src_port else src_ip,
                'destination': f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                'raw_data': data
            }
            new_alerts_data.append(alert_entry)

        # Sort alerts
        sort_col = self.alerts_sort_column
        if sort_col not in ['timestamp', 'signature', 'source', 'destination', 'category', 'intel']:
            sort_col = 'timestamp'
        new_alerts_data.sort(key=lambda x: x.get(sort_col, ''),
                              reverse=self.alerts_sort_reverse)

        # Apply hidden filters
        new_alerts_data = self._apply_alert_filters(new_alerts_data)

        # Group similar alerts by signature (before limiting)
        new_alerts_data = self._group_alerts_by_signature(new_alerts_data)

        # Limit to last 200 grouped alerts
        new_alerts_data = new_alerts_data[-200:]

        # Apply threat intel status for all alerts (check both src and dst IPs)
        for alert in new_alerts_data:
            src_ip = alert['source'].split(':')[0] if ':' in alert['source'] else alert['source']
            dst_ip = alert['destination'].split(':')[0] if ':' in alert['destination'] else alert['destination']
            sev = alert['severity']

            # Get cached intel results for both IPs
            src_intel = self.ip_tracker.get_result(src_ip)
            dst_intel = self.ip_tracker.get_result(dst_ip)

            # Combine intel results - show worst case
            intel_status = self._combine_intel_status(src_intel, dst_intel)

            if intel_status:
                alert['intel'] = intel_status
            elif sev in (1, 2):
                # For severity 1-2 alerts, auto-lookup public IPs that haven't been checked
                lookup_needed = False
                if self.ip_tracker.should_lookup(src_ip) and not is_private_ip(src_ip):
                    self._auto_lookup_ip(src_ip)
                    lookup_needed = True
                if self.ip_tracker.should_lookup(dst_ip) and not is_private_ip(dst_ip):
                    self._auto_lookup_ip(dst_ip)
                    lookup_needed = True
                alert['intel'] = 'checking' if lookup_needed else '-'
            else:
                alert['intel'] = '-'

        # Build list of new values tuples for comparison (must match display format)
        new_values = []
        for alert in new_alerts_data:
            sev = alert['severity']
            cat = alert['category']
            new_values.append((
                self._format_alert_timestamp(alert['timestamp']),
                str(sev),
                alert['signature'],
                alert['source'],
                alert['destination'],
                cat[:8] if len(cat) > 8 else cat,
                alert['intel']
            ))

        # Get current treeview values
        current_items = self.alerts_tree.get_children()
        current_values = []
        for item in current_items:
            current_values.append(self.alerts_tree.item(item, 'values'))

        # Reverse current_values since we insert at position 0
        current_values = list(reversed(current_values))

        # Compare - only update if data changed
        if new_values == current_values:
            # No changes, skip visual update entirely
            self.alerts_data = new_alerts_data
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.alerts_tree.yview()
        selected = self.alerts_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.alerts_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate
        for item in current_items:
            self.alerts_tree.delete(item)

        self.alerts_data = new_alerts_data

        for alert in new_alerts_data:
            sev = alert['severity']
            tag = 'high' if sev == 1 else 'medium' if sev == 2 else 'low'

            self.alerts_tree.insert('', 0, values=(
                self._format_alert_timestamp(alert['timestamp']),
                sev,
                alert['signature'],
                alert['source'],
                alert['destination'],
                alert['category'][:8] if len(alert['category']) > 8 else alert['category'],
                alert['intel']
            ), tags=(tag,))

        # Restore scroll position
        self.alerts_tree.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.alerts_tree.get_children():
                if self.alerts_tree.item(item, 'values') == selected_values:
                    self.alerts_tree.selection_set(item)
                    break

    def _on_alerts_tree_resize(self, event):
        """Auto-resize alerts columns when window resizes"""
        # Debounce resize events
        if hasattr(self, '_resize_after_id'):
            self.root.after_cancel(self._resize_after_id)
        self._resize_after_id = self.root.after(100, lambda: self._do_alerts_resize(event.width))

    def _do_alerts_resize(self, total_width):
        """Perform the actual column resize calculation"""
        if total_width < 100:
            return  # Ignore invalid widths

        # Fixed-width columns (don't scale)
        fixed_cols = {
            'timestamp': 70,
            'sev': 35,
            'category': 50,
            'intel': 90
        }
        fixed_total = sum(fixed_cols.values())

        # Remaining width for flexible columns (signature, source, destination)
        remaining = total_width - fixed_total - 20  # 20px for scrollbar

        if remaining > 0:
            # Signature gets 50%, source/destination get 25% each
            sig_width = max(150, int(remaining * 0.50))
            ip_width = max(90, int(remaining * 0.25))

            self.alerts_tree.column('signature', width=sig_width)
            self.alerts_tree.column('source', width=ip_width)
            self.alerts_tree.column('destination', width=ip_width)

    def sort_alerts(self, column):
        """Sort alerts by column"""
        if self.alerts_sort_column == column:
            self.alerts_sort_reverse = not self.alerts_sort_reverse
        else:
            self.alerts_sort_column = column
            self.alerts_sort_reverse = True

        self.refresh_alerts()

    def _set_time_range(self, preset: str):
        """Set time range preset and load appropriate data"""
        from datetime import datetime, timedelta

        # Store the selected preset for persistence across refreshes
        self.selected_time_range = preset
        today = datetime.now()

        if preset == 'live':
            # Switch back to live mode
            self.historical_mode = False
            self.historical_alerts = []
            self.date_from_var.set("")
            self.date_to_var.set("")
            self.date_filter_frame.pack_forget()
            self.time_range_status.configure(
                text=f"󰋚 Live (last {self.data_retention_minutes} min)",
                foreground=self.colors['green']
            )
            self.refresh_alerts()

        elif preset == '24h':
            date_from = (today - timedelta(days=1)).strftime('%Y-%m-%d')
            date_to = today.strftime('%Y-%m-%d')
            self._load_historical_logs(date_from, date_to, "Last 24 hours")

        elif preset == '7d':
            date_from = (today - timedelta(days=7)).strftime('%Y-%m-%d')
            date_to = today.strftime('%Y-%m-%d')
            self._load_historical_logs(date_from, date_to, "Last 7 days")

        elif preset == '30d':
            date_from = (today - timedelta(days=30)).strftime('%Y-%m-%d')
            date_to = today.strftime('%Y-%m-%d')
            self._load_historical_logs(date_from, date_to, "Last 30 days")

    def _show_custom_date_dialog(self):
        """Show dialog for custom date range selection"""
        from datetime import datetime, timedelta

        dialog = tk.Toplevel(self.root)
        dialog.title("Custom Date Range")
        dialog.geometry("350x200")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="󰃭 Select Date Range", font=('Hack Nerd Font', 12, 'bold')).pack(pady=10)

        # Date inputs
        input_frame = ttk.Frame(dialog)
        input_frame.pack(pady=10)

        today = datetime.now()
        week_ago = (today - timedelta(days=7)).strftime('%Y-%m-%d')
        today_str = today.strftime('%Y-%m-%d')

        ttk.Label(input_frame, text="From:").grid(row=0, column=0, padx=5, pady=5)
        from_var = tk.StringVar(value=week_ago)
        from_entry = self.widgets.create_entry(input_frame, textvariable=from_var, width=15)
        from_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="To:").grid(row=1, column=0, padx=5, pady=5)
        to_var = tk.StringVar(value=today_str)
        to_entry = self.widgets.create_entry(input_frame, textvariable=to_var, width=15)
        to_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Format: YYYY-MM-DD", foreground=self.colors['gray']).pack()

        def apply_range():
            date_from = from_var.get().strip()
            date_to = to_var.get().strip()

            # Validate dates
            try:
                datetime.strptime(date_from, '%Y-%m-%d')
                datetime.strptime(date_to, '%Y-%m-%d')
            except ValueError:
                messagebox.showerror("Invalid Date", "Please use YYYY-MM-DD format")
                return

            dialog.destroy()
            self.selected_time_range = 'custom'
            self._load_historical_logs(date_from, date_to, f"{date_from} to {date_to}")

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=15)
        self.widgets.create_button(btn_frame, text="Load", command=apply_range).pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _load_historical_logs(self, date_from: str, date_to: str, label: str):
        """Load historical logs from files within date range"""
        import gzip
        from datetime import datetime

        def do_load():
            self.show_progress(f"Loading logs for {label}...")

            try:
                log_dir = Path("/var/log/suricata")
                all_alerts = []

                # Find all relevant log files
                log_files = []

                # Current eve.json
                current_log = log_dir / "eve.json"
                if current_log.exists():
                    log_files.append(('current', current_log))

                # Rotated logs (eve.json-YYYYMMDD and eve.json-YYYYMMDD.gz)
                for f in log_dir.glob("eve.json-*"):
                    log_files.append(('rotated', f))

                # Sort by modification time (newest first)
                log_files.sort(key=lambda x: x[1].stat().st_mtime, reverse=True)

                parsed_count = 0
                for file_type, log_file in log_files:
                    try:
                        # Check if file might contain data in our range
                        file_date = None
                        if file_type == 'rotated':
                            # Extract date from filename like eve.json-20260104
                            name = log_file.name
                            if name.endswith('.gz'):
                                name = name[:-3]
                            date_part = name.split('-')[-1]
                            if len(date_part) == 8 and date_part.isdigit():
                                file_date = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
                                # Skip if file is outside our range
                                if file_date < date_from or file_date > date_to:
                                    continue

                        # Read the file
                        if str(log_file).endswith('.gz'):
                            with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                        else:
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()

                        # Parse each line
                        for line in lines:
                            try:
                                data = json.loads(line.strip())
                                if data.get('event_type') != 'alert':
                                    continue

                                timestamp = data.get('timestamp', '')[:19]
                                event_date = timestamp[:10]

                                # Filter by date range
                                if event_date < date_from or event_date > date_to:
                                    continue

                                alert_data = data.get('alert', {})
                                severity = alert_data.get('severity', 3)
                                src_ip = data.get('src_ip', 'N/A')
                                dst_ip = data.get('dest_ip', 'N/A')
                                src_port = data.get('src_port', '')
                                dst_port = data.get('dest_port', '')

                                all_alerts.append({
                                    'timestamp': timestamp,
                                    'severity': severity,
                                    'engine': 'Suricata',
                                    'signature': alert_data.get('signature', 'Unknown'),
                                    'category': alert_data.get('category', 'Unknown'),
                                    'source': f"{src_ip}:{src_port}" if src_port else src_ip,
                                    'destination': f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                                    'raw_data': data
                                })
                                parsed_count += 1

                            except (json.JSONDecodeError, KeyError):
                                continue

                    except Exception as e:
                        print(f"Error reading {log_file}: {e}")
                        continue

                # Sort by timestamp (newest first)
                all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)

                def update_ui():
                    self.hide_progress()
                    self.historical_mode = True
                    self.historical_alerts = all_alerts
                    self.date_from_var.set(date_from)
                    self.date_to_var.set(date_to)

                    self.time_range_status.configure(
                        text=f"󰋚 Historical: {label} ({len(all_alerts)} alerts)",
                        foreground=self.colors['cyan']
                    )

                    # Show the date filter frame for manual adjustment
                    self.date_filter_frame.pack(side=tk.LEFT, padx=(10, 0))

                    # Refresh display with historical data
                    self._refresh_historical_alerts()

                self.root.after(0, update_ui)

            except Exception as e:
                error_msg = str(e)
                def show_error(msg=error_msg):
                    self.hide_progress()
                    messagebox.showerror("Error", f"Failed to load logs: {msg}")
                self.root.after(0, show_error)

        threading.Thread(target=do_load, daemon=True).start()

    def _refresh_historical_alerts(self):
        """Refresh alerts display with historical data (silent refresh)"""
        if not self.historical_mode:
            # Not in historical mode, nothing to do
            return

        severity_filter = self.severity_var.get()
        date_from = self.date_from_var.get().strip()
        date_to = self.date_to_var.get().strip()

        # Filter historical alerts
        filtered = []
        for alert in self.historical_alerts:
            # Severity filter
            if severity_filter != "all":
                filter_sev = int(severity_filter[0])
                if alert['severity'] != filter_sev:
                    continue

            # Additional date filtering
            timestamp = alert['timestamp']
            if date_from and timestamp[:10] < date_from:
                continue
            if date_to and timestamp[:10] > date_to:
                continue

            filtered.append(alert)

        # Sort
        sort_col = self.alerts_sort_column
        filtered.sort(key=lambda x: x.get(sort_col, ''), reverse=self.alerts_sort_reverse)

        # Apply hidden filters
        filtered = self._apply_alert_filters(filtered)

        # Group similar alerts by signature
        filtered = self._group_alerts_by_signature(filtered)

        # Limit display to 500 grouped alerts for performance
        filtered = filtered[:500]

        # Add intel status for historical alerts (check both src and dst IPs)
        for alert in filtered:
            src_ip = alert['source'].split(':')[0] if ':' in alert['source'] else alert['source']
            dst_ip = alert['destination'].split(':')[0] if ':' in alert['destination'] else alert['destination']

            # Get cached intel results for both IPs
            src_intel = self.ip_tracker.get_result(src_ip)
            dst_intel = self.ip_tracker.get_result(dst_ip)

            # Combine intel results - show worst case
            intel_status = self._combine_intel_status(src_intel, dst_intel)
            alert['intel'] = intel_status if intel_status else '-'

        # Build list of new values tuples for comparison (must match display format)
        new_values = []
        for alert in filtered:
            sev = alert['severity']
            cat = alert['category']
            new_values.append((
                self._format_alert_timestamp(alert['timestamp']),
                str(sev),
                alert['signature'],
                alert['source'],
                alert['destination'],
                cat[:8] if len(cat) > 8 else cat,
                alert['intel']
            ))

        # Get current treeview values
        current_items = self.alerts_tree.get_children()
        current_values = [self.alerts_tree.item(item, 'values') for item in current_items]

        # Compare - only update if data changed (silent refresh)
        if new_values == current_values:
            self.alerts_data = filtered
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.alerts_tree.yview()
        selected = self.alerts_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.alerts_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate
        for item in current_items:
            self.alerts_tree.delete(item)

        self.alerts_data = filtered

        for alert in filtered:
            sev = alert['severity']
            tag = 'high' if sev == 1 else ('medium' if sev == 2 else 'low')
            self.alerts_tree.insert('', tk.END, values=(
                self._format_alert_timestamp(alert['timestamp']),
                sev,
                alert['signature'],
                alert['source'],
                alert['destination'],
                alert['category'][:8] if len(alert['category']) > 8 else alert['category'],
                alert['intel']
            ), tags=(tag,))

        # Restore scroll position
        self.alerts_tree.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.alerts_tree.get_children():
                if self.alerts_tree.item(item, 'values') == selected_values:
                    self.alerts_tree.selection_set(item)
                    break

    def filter_alerts_treeview(self, search_text):
        """Filter alerts treeview based on search text"""
        if not search_text:
            # Show all - just refresh
            self.refresh_alerts()
            return

        # Filter visible items
        for item in self.alerts_tree.get_children():
            values = self.alerts_tree.item(item, 'values')
            match = any(search_text in str(v).lower() for v in values)
            if not match:
                self.alerts_tree.detach(item)

    def show_alert_details(self, event):
        """Show alert details in popup window"""
        selection = self.alerts_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.alerts_tree.item(item, 'values')
        # Columns: timestamp, sev, signature, source, destination, category, intel
        display_ts, sev, signature, source, destination = values[0], values[1], values[2], values[3], values[4]

        # Find the full alert data by matching signature and source (timestamps may be formatted)
        alert_data = None
        alert_obj = None
        for alert in self.alerts_data:
            # Match by signature + source (more reliable than formatted timestamp)
            if alert['signature'] == signature and alert['source'] == source:
                # Also verify severity matches
                if str(alert['severity']) == str(sev):
                    alert_data = alert.get('raw_data', {})
                    alert_obj = alert
                    break

        if not alert_data:
            return

        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title(f"Alert Details - {signature[:50]}")
        popup.geometry("700x500")
        popup.configure(bg=self.colors['bg'])

        # Header - get severity from alert_obj
        header_frame = ttk.Frame(popup)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        sev = str(alert_obj.get('severity', '3')) if alert_obj else '3'
        sev_color = self.colors['red'] if sev == '1' else self.colors['orange'] if sev == '2' else self.colors['yellow']
        engine = alert_obj.get('engine', 'Unknown') if alert_obj else 'Unknown'
        intel = values[5] if len(values) > 5 else '-'
        tk.Label(header_frame, text=f"Severity {sev} ({engine}) | Intel: {intel}", font=('Hack Nerd Font', 12, 'bold'),
                 bg=self.colors['bg'], fg=sev_color).pack(side=tk.LEFT)
        tk.Label(header_frame, text=timestamp, font=('Hack Nerd Font', 10),
                 bg=self.colors['bg'], fg=self.colors['gray']).pack(side=tk.RIGHT)

        # Signature
        ttk.Label(popup, text=signature, font=('Hack Nerd Font', 11, 'bold'),
                  wraplength=680).pack(anchor=tk.W, padx=10, pady=5)

        # Connection info
        conn_frame = ttk.Frame(popup)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(conn_frame, text=f"Source: {source}").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(conn_frame, text=f"Destination: {destination}").pack(side=tk.LEFT)

        # Full JSON data
        ttk.Label(popup, text="Raw Event Data:", font=('Hack Nerd Font', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(10, 5))

        json_text = self.widgets.create_textbox(popup, height=20, bg=self.colors['bg_alt'],
                                              fg=self.colors['fg'], font=('Hack Nerd Font', 9))
        json_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        json_text.insert(tk.END, json.dumps(alert_data, indent=2))
        json_text.configure(state='disabled')

        # Buttons
        btn_frame = ttk.Frame(popup)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.widgets.create_button(btn_frame, text="Copy JSON", command=lambda: self.copy_to_clipboard(
            json.dumps(alert_data, indent=2))).pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(btn_frame, text="Close", command=popup.destroy).pack(side=tk.RIGHT, padx=5)

    def show_alert_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.alerts_tree.identify_row(event.y)
        if not item:
            return

        self.alerts_tree.selection_set(item)
        values = self.alerts_tree.item(item, 'values')
        # Columns: timestamp, sev, signature, source, destination, category, intel
        signature = values[2]
        # Strip x{count} suffix from grouped signatures (e.g., "ET INFO... x10" -> "ET INFO...")
        signature = re.sub(r'\s+x\d+$', '', signature)
        src_ip = values[3].split(':')[0] if ':' in str(values[3]) else str(values[3])
        dest_ip = values[4].split(':')[0] if ':' in str(values[4]) else str(values[4])

        menu = tk.Menu(self.root, tearoff=0, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        menu.add_command(label="View Details", command=lambda: self.show_alert_details(None))
        menu.add_command(label="Copy Row", command=lambda: self.copy_to_clipboard('\t'.join(str(v) for v in values)))
        menu.add_separator()
        menu.add_command(label=f"Search Source: {src_ip}",
                        command=lambda: self.search_var.set(src_ip))
        menu.add_command(label=f"Search Dest: {dest_ip}",
                        command=lambda: self.search_var.set(dest_ip))
        menu.add_command(label=f"Search Signature",
                        command=lambda: self.search_var.set(signature))
        menu.add_separator()

        # Threat Intelligence submenu
        ti_menu = tk.Menu(menu, tearoff=0, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        ti_menu.add_command(label=f"VirusTotal: {src_ip}",
                           command=lambda: self.lookup_virustotal(src_ip))
        ti_menu.add_command(label=f"VirusTotal: {dest_ip}",
                           command=lambda: self.lookup_virustotal(dest_ip))
        ti_menu.add_separator()
        ti_menu.add_command(label=f"OTX: {src_ip}",
                           command=lambda: self.lookup_otx(src_ip))
        ti_menu.add_command(label=f"OTX: {dest_ip}",
                           command=lambda: self.lookup_otx(dest_ip))
        menu.add_cascade(label="󰊕 Threat Intel", menu=ti_menu)

        menu.add_separator()

        # Hide/Filter submenu
        category = values[4] if len(values) > 4 else ''
        hide_menu = tk.Menu(menu, tearoff=0, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        hide_menu.add_command(label=f"Hide Signature: {signature[:40]}...",
                             command=lambda s=signature: self._hide_signature(s))
        hide_menu.add_command(label=f"Hide Source IP: {src_ip}",
                             command=lambda ip=src_ip: self._hide_src_ip(ip))
        hide_menu.add_command(label=f"Hide Dest IP: {dest_ip}",
                             command=lambda ip=dest_ip: self._hide_dest_ip(ip))
        if category:
            hide_menu.add_command(label=f"Hide Category: {category}",
                                 command=lambda c=category: self._hide_category(c))
        hide_menu.add_separator()
        hide_menu.add_command(label="Manage Filters...", command=self._show_filter_manager)
        menu.add_cascade(label="󰈲 Hide/Filter", menu=hide_menu)

        menu.post(event.x_root, event.y_root)

    def lookup_virustotal(self, ip: str):
        """Lookup IP on VirusTotal and show results"""
        def do_lookup():
            result = self.vt_client.lookup_ip(ip)
            def show():
                self._add_to_lookup_history(ip, 'VirusTotal', result)
                self._show_threat_intel_result("VirusTotal", ip, result)
            self.root.after(0, show)

        self.show_progress("Looking up on VirusTotal...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def lookup_otx(self, ip: str):
        """Lookup IP on AlienVault OTX and show results"""
        def do_lookup():
            result = self.otx_client.lookup_ip(ip)
            def show():
                self._add_to_lookup_history(ip, 'OTX', result)
                self._show_threat_intel_result("OTX", ip, result)
            self.root.after(0, show)

        self.show_progress("Looking up on OTX...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def _auto_lookup_ip(self, ip: str):
        """Automatically lookup IP via AbuseIPDB and record result (for severity 1 alerts)"""
        def do_lookup():
            try:
                # Use AbuseIPDB for auto-lookup (best for IP reputation)
                result = self.abuseipdb_client.lookup_ip(ip)

                # Determine danger status based on abuse score
                if 'error' in result:
                    status = 'error'
                    details = {'error': result.get('error', 'Unknown error')}
                else:
                    # AbuseIPDB client returns snake_case field names
                    abuse_score = result.get('abuse_score', 0)
                    total_reports = result.get('total_reports', 0)

                    if abuse_score >= 50 or total_reports >= 10:
                        status = 'DANGER'
                    elif abuse_score >= 25 or total_reports >= 3:
                        status = 'suspect'
                    else:
                        status = 'safe'

                    # Store details using consistent key names for display
                    details = {
                        'abuseConfidenceScore': abuse_score,
                        'totalReports': total_reports,
                        'countryCode': result.get('country', ''),
                        'isp': result.get('isp', ''),
                        'domain': result.get('domain', ''),
                        'usageType': result.get('usage_type', '')
                    }

                # Record result in tracker with full details
                self.ip_tracker.record_lookup(ip, status, source='AbuseIPDB', details=details)

                # Add to Intel tab lookup history on main thread
                def update_ui():
                    self._add_to_lookup_history(ip, 'AbuseIPDB', result)
                    self._refresh_intel_from_tracker()
                    self.refresh_alerts()

                self.root.after(100, update_ui)

            except Exception as e:
                print(f"Auto-lookup error for {ip}: {e}")
                self.ip_tracker.record_lookup(ip, 'error', source='AbuseIPDB',
                                              details={'error': str(e)})

        threading.Thread(target=do_lookup, daemon=True).start()

    # ==================== Alert Filtering Methods ====================

    def _hide_signature(self, signature: str):
        """Add signature to hidden filter (persisted)"""
        self.hidden_signatures.add(signature)
        self._update_filter_count()
        self.save_filters()
        self.refresh_alerts()

    def _hide_src_ip(self, ip: str):
        """Add source IP to hidden filter (persisted)"""
        self.hidden_src_ips.add(ip)
        self._update_filter_count()
        self.save_filters()
        self.refresh_alerts()

    def _hide_dest_ip(self, ip: str):
        """Add destination IP to hidden filter (persisted)"""
        self.hidden_dest_ips.add(ip)
        self._update_filter_count()
        self.save_filters()
        self.refresh_alerts()

    def _hide_category(self, category: str):
        """Add category to hidden filter (persisted)"""
        self.hidden_categories.add(category)
        self._update_filter_count()
        self.save_filters()
        self.refresh_alerts()

    def _update_filter_count(self):
        """Update filter count indicator"""
        total = len(self.hidden_signatures) + len(self.hidden_src_ips) + \
                len(self.hidden_dest_ips) + len(self.hidden_categories)
        if total > 0:
            self.filter_count_label.configure(text=f"({total} filters)")
        else:
            self.filter_count_label.configure(text="")

    def _show_filter_manager(self):
        """Show dialog to manage hidden filters"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage Alert Filters")
        dialog.geometry("600x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)

        # Header
        ttk.Label(dialog, text="󰈲 Alert Filters", font=('Hack Nerd Font', 14, 'bold')).pack(pady=10)
        ttk.Label(dialog, text="Items in these lists will be hidden from alerts view",
                 foreground=self.colors['gray']).pack()

        # Notebook for filter categories
        filter_nb = ttk.Notebook(dialog)
        filter_nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create listboxes for each filter type
        self._filter_listboxes = {}

        filter_types = [
            ('signatures', 'Hidden Signatures', self.hidden_signatures),
            ('src_ips', 'Hidden Source IPs', self.hidden_src_ips),
            ('dest_ips', 'Hidden Dest IPs', self.hidden_dest_ips),
            ('categories', 'Hidden Categories', self.hidden_categories)
        ]

        for key, title, filter_set in filter_types:
            frame = ttk.Frame(filter_nb)
            filter_nb.add(frame, text=title)

            # Listbox with scrollbar
            list_frame = ttk.Frame(frame)
            list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            scrollbar = ttk.Scrollbar(list_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            listbox = tk.Listbox(list_frame, bg=self.colors['bg_alt'], fg=self.colors['fg'],
                                font=('Hack Nerd Font', 10), selectmode=tk.EXTENDED,
                                yscrollcommand=scrollbar.set)
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)

            for item in sorted(filter_set):
                listbox.insert(tk.END, item)

            self._filter_listboxes[key] = (listbox, filter_set)

            # Remove button
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(fill=tk.X, padx=5, pady=5)
            self.widgets.create_button(btn_frame, text="Remove Selected",
                command=lambda k=key: self._remove_selected_filter(k)).pack(side=tk.LEFT, padx=5)
            self.widgets.create_button(btn_frame, text="Clear All",
                command=lambda k=key: self._clear_filter(k)).pack(side=tk.LEFT, padx=5)

        # Bottom buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        self.widgets.create_button(btn_frame, text="Clear All Filters",
            command=lambda: self._clear_all_filters(dialog)).pack(side=tk.LEFT, padx=5)
        self.widgets.create_button(btn_frame, text="Close",
            command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def _remove_selected_filter(self, filter_key: str):
        """Remove selected items from filter"""
        if filter_key not in self._filter_listboxes:
            return

        listbox, filter_set = self._filter_listboxes[filter_key]
        selected = listbox.curselection()

        # Get items to remove (in reverse order to maintain indices)
        items_to_remove = [listbox.get(i) for i in selected]

        for item in items_to_remove:
            filter_set.discard(item)

        # Refresh listbox
        listbox.delete(0, tk.END)
        for item in sorted(filter_set):
            listbox.insert(tk.END, item)

        self._update_filter_count()
        self.save_filters()
        self.refresh_alerts()

    def _clear_filter(self, filter_key: str):
        """Clear all items from a specific filter"""
        if filter_key not in self._filter_listboxes:
            return

        listbox, filter_set = self._filter_listboxes[filter_key]
        filter_set.clear()
        listbox.delete(0, tk.END)

        self._update_filter_count()
        self.save_filters()
        self.refresh_alerts()

    def _clear_all_filters(self, dialog):
        """Clear all filters"""
        self.hidden_signatures.clear()
        self.hidden_src_ips.clear()
        self.hidden_dest_ips.clear()
        self.hidden_categories.clear()
        self._update_filter_count()
        self.refresh_alerts()
        dialog.destroy()

    def _format_alert_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display - compact for recent, full for older.

        Shows time only (HH:MM:SS) for today's alerts, adds date for older ones.
        """
        if not timestamp or len(timestamp) < 19:
            return timestamp or ''

        today = datetime.now().strftime('%Y-%m-%d')
        alert_date = timestamp[:10]

        if alert_date == today:
            # Today: show time only
            return timestamp[11:19]  # HH:MM:SS
        else:
            # Older: show MM-DD HH:MM
            return f"{timestamp[5:10]} {timestamp[11:16]}"

    def _combine_intel_status(self, src_intel: str, dst_intel: str) -> str:
        """Combine intel status from source and destination IPs.

        Returns the most severe status, prioritizing:
        DANGER > suspect > error > checking > safe > None

        Args:
            src_intel: Intel status for source IP (or None)
            dst_intel: Intel status for destination IP (or None)

        Returns:
            Combined status string or None if no intel available
        """
        # Priority order (highest to lowest severity)
        priority = {'DANGER': 5, 'suspect': 4, 'error': 3, 'checking': 2, 'safe': 1}

        src_priority = priority.get(src_intel, 0) if src_intel else 0
        dst_priority = priority.get(dst_intel, 0) if dst_intel else 0

        if src_priority == 0 and dst_priority == 0:
            return None

        # Return the most severe status
        if src_priority >= dst_priority:
            return src_intel
        return dst_intel

    def _apply_alert_filters(self, alerts: list) -> list:
        """Apply hidden filters to alert list"""
        if not (self.hidden_signatures or self.hidden_src_ips or
                self.hidden_dest_ips or self.hidden_categories):
            return alerts

        filtered = []
        for alert in alerts:
            signature = alert.get('signature', '')
            src = alert.get('source', '').split(':')[0]
            dest = alert.get('destination', '').split(':')[0]
            category = alert.get('category', '')

            # Skip if any filter matches
            if signature in self.hidden_signatures:
                continue
            if src in self.hidden_src_ips:
                continue
            if dest in self.hidden_dest_ips:
                continue
            if category in self.hidden_categories:
                continue

            filtered.append(alert)

        return filtered

    def _group_alerts_by_signature(self, alerts: list) -> list:
        """Group similar alerts by signature, appending x{count} for duplicates.

        Groups alerts with the same signature, keeping the most recent occurrence
        and appending a count indicator (e.g., "ET INFO EXTERNAL IP Lookup x10").
        """
        if not alerts:
            return alerts

        # Group by signature
        signature_groups = {}
        for alert in alerts:
            sig = alert.get('signature', 'Unknown')
            if sig not in signature_groups:
                signature_groups[sig] = []
            signature_groups[sig].append(alert)

        # Build grouped result - use most recent alert from each group
        grouped_alerts = []
        for sig, group in signature_groups.items():
            # Sort group by timestamp descending to get most recent
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()  # Copy to avoid modifying original

            count = len(group)
            if count > 1:
                # Append count to signature
                most_recent['signature'] = f"{sig} x{count}"
                most_recent['_group_count'] = count  # Store for potential use

            grouped_alerts.append(most_recent)

        # Sort grouped alerts by timestamp (most recent first for display)
        grouped_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return grouped_alerts

    def _show_threat_intel_result(self, source: str, indicator: str, result: dict):
        """Display threat intelligence lookup result in a dialog"""
        self.hide_progress()

        dialog = tk.Toplevel(self.root)
        dialog.title(f"{source} Lookup: {indicator}")
        dialog.geometry("500x400")
        dialog.configure(bg=self.colors['bg'])

        # Header
        header = ttk.Label(dialog, text=f"󰊕 {source} Results", font=('Hack Nerd Font', 14, 'bold'))
        header.pack(pady=10)

        # Result display - use ScrolledText for tag_configure support
        text = scrolledtext.ScrolledText(dialog, height=15, bg=self.colors['bg_alt'],
                                          fg=self.colors['fg'], font=('Hack Nerd Font', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        if 'error' in result:
            text.insert(tk.END, f"Error: {result['error']}\n\n")
            text.insert(tk.END, "Tips:\n")
            text.insert(tk.END, "- Check if API key is configured in Settings > Threat Intel\n")
            text.insert(tk.END, "- Check your internet connection\n")
            text.insert(tk.END, "- Public API has rate limits (4 req/min for VirusTotal)\n")
        else:
            text.insert(tk.END, f"Indicator: {result.get('indicator', indicator)}\n")
            text.insert(tk.END, f"Type: {result.get('type', 'Unknown')}\n\n")

            if source == "VirusTotal":
                malicious = result.get('malicious', 0)
                suspicious = result.get('suspicious', 0)
                harmless = result.get('harmless', 0)

                # Threat score
                if malicious > 0:
                    text.insert(tk.END, f"⚠ MALICIOUS: {malicious} detections\n", 'danger')
                elif suspicious > 0:
                    text.insert(tk.END, f"⚡ SUSPICIOUS: {suspicious} flags\n", 'warning')
                else:
                    text.insert(tk.END, f"✓ CLEAN: No detections\n", 'safe')

                text.insert(tk.END, f"\nReputation Score: {result.get('reputation', 0)}\n")
                text.insert(tk.END, f"Country: {result.get('country', 'Unknown')}\n")
                text.insert(tk.END, f"AS Owner: {result.get('as_owner', 'Unknown')}\n")
                text.insert(tk.END, f"\nStats: {malicious} malicious, {suspicious} suspicious, {harmless} harmless\n")

            elif source == "OTX":
                pulse_count = result.get('pulse_count', 0)

                if pulse_count > 0:
                    text.insert(tk.END, f"⚠ Found in {pulse_count} threat pulse(s)\n\n", 'danger')
                    text.insert(tk.END, "Related Pulses:\n")
                    for pulse in result.get('pulses', []):
                        text.insert(tk.END, f"  • {pulse}\n")
                else:
                    text.insert(tk.END, "✓ Not found in any threat pulses\n", 'safe')

                text.insert(tk.END, f"\nCountry: {result.get('country', 'Unknown')}\n")

            elif source == "ThreatFox":
                found = result.get('found', False)

                if found:
                    text.insert(tk.END, f"⚠ THREAT FOUND\n\n", 'danger')
                    text.insert(tk.END, f"Malware Family: {result.get('malware', 'Unknown')}\n")
                    text.insert(tk.END, f"Threat Type: {result.get('threat_type', 'Unknown')}\n")
                    text.insert(tk.END, f"Confidence: {result.get('confidence', 'Unknown')}%\n")
                    text.insert(tk.END, f"First Seen: {result.get('first_seen', 'Unknown')}\n")
                    text.insert(tk.END, f"Last Seen: {result.get('last_seen', 'Unknown')}\n")
                    tags = result.get('tags', [])
                    if tags:
                        text.insert(tk.END, f"\nTags: {', '.join(tags)}\n")
                    reporter = result.get('reporter', '')
                    if reporter:
                        text.insert(tk.END, f"Reporter: {reporter}\n")
                else:
                    text.insert(tk.END, "✓ Not found in ThreatFox database\n", 'safe')
                    text.insert(tk.END, "\nThis IOC is not associated with known malware.\n")

            elif source == "AbuseIPDB":
                score = result.get('abuse_score', 0)
                total_reports = result.get('total_reports', 0)

                if score >= 50:
                    text.insert(tk.END, f"⚠ HIGH ABUSE SCORE: {score}%\n\n", 'danger')
                elif score > 0:
                    text.insert(tk.END, f"⚡ MODERATE ABUSE SCORE: {score}%\n\n", 'warning')
                else:
                    text.insert(tk.END, f"✓ CLEAN: Abuse score 0%\n\n", 'safe')

                text.insert(tk.END, f"Total Reports: {total_reports}\n")
                text.insert(tk.END, f"Country: {result.get('country', 'Unknown')}\n")
                text.insert(tk.END, f"ISP: {result.get('isp', 'Unknown')}\n")
                text.insert(tk.END, f"Domain: {result.get('domain', 'Unknown')}\n")
                text.insert(tk.END, f"Usage Type: {result.get('usage_type', 'Unknown')}\n")

                if result.get('is_tor', False):
                    text.insert(tk.END, "\n⚠ This IP is a known Tor exit node\n", 'warning')
                if result.get('is_whitelisted', False):
                    text.insert(tk.END, "\n✓ This IP is whitelisted\n", 'safe')

        # Apply text tags for coloring
        text.tag_configure('danger', foreground=self.colors['red'])
        text.tag_configure('warning', foreground=self.colors['yellow'])
        text.tag_configure('safe', foreground=self.colors['green'])

        text.configure(state='disabled')

        # Close button
        self.widgets.create_button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def export_alerts(self):
        """Export alerts to CSV file"""
        if not self.alerts_data:
            messagebox.showinfo("Export", "No alerts to export")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        if not filepath:
            return

        try:
            if filepath.endswith('.json'):
                with open(filepath, 'w') as f:
                    # Export raw data without the raw_data field to avoid duplication
                    export_data = [{k: v for k, v in a.items() if k != 'raw_data'} for a in self.alerts_data]
                    json.dump(export_data, f, indent=2)
            else:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Severity', 'Signature', 'Source', 'Destination', 'Category'])
                    for alert in self.alerts_data:
                        writer.writerow([
                            alert['timestamp'], alert['severity'], alert['signature'],
                            alert['source'], alert['destination'], alert['category']
                        ])

            messagebox.showinfo("Export", f"Exported {len(self.alerts_data)} alerts to {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def refresh_traffic(self):
        """Refresh traffic analysis from shared EVE buffer"""
        # Update the shared buffer first
        self._update_eve_buffer()

        # Get protocol filter
        proto_filter = self.traffic_proto_filter.get().lower()

        # Build traffic entries
        traffic_entries = []
        protocols = {}

        for entry in self.eve_event_buffer:
            data = entry['data']
            event = data.get('event_type', '')

            # Skip non-traffic events and DNS (has its own tab)
            if event not in ['http', 'tls', 'ssh', 'rdp', 'smb']:
                continue

            protocols[event] = protocols.get(event, 0) + 1

            # Apply filter
            if proto_filter != "all" and event != proto_filter:
                continue

            src_ip = data.get('src_ip', '')
            src_port = data.get('src_port', '')
            dest_ip = data.get('dest_ip', '')
            dest_port = data.get('dest_port', '')

            source = f"{src_ip}:{src_port}" if src_port else src_ip
            destination = f"{dest_ip}:{dest_port}" if dest_port else dest_ip

            host = ''
            details = ''

            if event == 'http':
                http = data.get('http', {})
                host = http.get('hostname', '')
                method = http.get('http_method', 'GET')
                url = http.get('url', '/')
                status = http.get('status', '')
                length = http.get('length', '')

                # Truncate URL if too long
                if len(url) > 40:
                    url = url[:37] + '...'
                details = f"{method} {url}"
                if status:
                    details += f" [{status}]"

            elif event == 'tls':
                tls = data.get('tls', {})
                host = tls.get('sni', '')
                version = tls.get('version', '')
                subject = tls.get('subject', '')
                ja3 = tls.get('ja3', {}).get('hash', '') if isinstance(tls.get('ja3'), dict) else ''

                details = version
                if ja3:
                    details += f" JA3:{ja3[:12]}..."
                if subject and len(details) < 30:
                    details += f" {subject[:20]}"

            elif event == 'ssh':
                ssh = data.get('ssh', {})
                client = ssh.get('client', {})
                server = ssh.get('server', {})
                client_ver = client.get('software_version', '') if isinstance(client, dict) else ''
                server_ver = server.get('software_version', '') if isinstance(server, dict) else ''
                details = f"Client: {client_ver}" if client_ver else ''
                if server_ver:
                    details += f" → Server: {server_ver}"

            elif event == 'smb':
                smb = data.get('smb', {})
                command = smb.get('command', '')
                filename = smb.get('filename', '')
                details = f"{command}"
                if filename:
                    details += f" {filename[:30]}"

            elif event == 'rdp':
                rdp = data.get('rdp', {})
                details = rdp.get('event_type', '')

            traffic_entries.append({
                'timestamp': entry['timestamp'],
                'protocol': event.upper(),
                'source': source,
                'destination': destination,
                'host': host,
                'details': details,
                'raw_data': data
            })

        # Update cache
        self.traffic_cache = {
            'protocols': protocols,
            'last_update': datetime.now()
        }

        # Sort by selected column
        sort_col = self.traffic_sort_column
        traffic_entries.sort(key=lambda x: x.get(sort_col, ''), reverse=self.traffic_sort_reverse)

        # Apply grouping unless ungrouped view is selected
        if not self.traffic_ungrouped.get():
            traffic_entries = self._group_traffic_by_destination(traffic_entries)

        # Limit to 300 entries
        traffic_entries = traffic_entries[:300]

        # Update stats
        total = len(traffic_entries)
        proto_breakdown = ', '.join(f"{p.upper()}: {c}" for p, c in sorted(protocols.items(), key=lambda x: -x[1])[:4])
        self.traffic_stats_label.configure(text=f"{total} connections | {proto_breakdown}")

        # Build list of new values tuples for comparison
        new_values = []
        for entry in traffic_entries:
            new_values.append((
                entry['timestamp'],
                entry['protocol'],
                entry['source'],
                entry['destination'],
                entry['host'],
                entry['details']
            ))

        # Get current treeview values
        current_items = self.traffic_tree.get_children()
        current_values = [self.traffic_tree.item(item, 'values') for item in current_items]

        # Compare - only update if data changed (silent refresh)
        if new_values == current_values:
            self.traffic_data = traffic_entries
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.traffic_tree.yview()
        selected = self.traffic_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.traffic_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate treeview
        for item in current_items:
            self.traffic_tree.delete(item)

        self.traffic_data = traffic_entries

        for entry in traffic_entries:
            proto = entry['protocol'].lower()
            self.traffic_tree.insert('', tk.END, values=(
                entry['timestamp'],
                entry['protocol'],
                entry['source'],
                entry['destination'],
                entry['host'],
                entry['details']
            ), tags=(proto,))

        # Restore scroll position
        self.traffic_tree.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.traffic_tree.get_children():
                if self.traffic_tree.item(item, 'values') == selected_values:
                    self.traffic_tree.selection_set(item)
                    break

    def sort_traffic(self, column):
        """Sort traffic by column"""
        if self.traffic_sort_column == column:
            self.traffic_sort_reverse = not self.traffic_sort_reverse
        else:
            self.traffic_sort_column = column
            self.traffic_sort_reverse = True
        self.refresh_traffic()

    def _toggle_traffic_grouping(self):
        """Toggle between grouped and ungrouped traffic view"""
        current = self.traffic_ungrouped.get()
        self.traffic_ungrouped.set(not current)

        # Update button text to show current state
        if self.traffic_ungrouped.get():
            self.traffic_ungroup_btn.configure(text="󰘸 Group")
        else:
            self.traffic_ungroup_btn.configure(text="󰘷 Ungroup")

        self.refresh_traffic()

    def _group_traffic_by_destination(self, entries: list) -> list:
        """Group traffic entries by destination, appending x{count} for duplicates.

        Groups traffic with the same destination (IP:port), keeping the most recent
        occurrence and appending a count indicator (e.g., "192.168.1.1:443 x15").
        """
        if not entries:
            return entries

        # Group by destination
        dest_groups = {}
        for entry in entries:
            dest = entry.get('destination', '')
            if dest not in dest_groups:
                dest_groups[dest] = []
            dest_groups[dest].append(entry)

        # Build grouped result - use most recent entry from each group
        grouped_entries = []
        for dest, group in dest_groups.items():
            # Sort group by timestamp descending to get most recent
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()  # Copy to avoid modifying original

            count = len(group)
            if count > 1:
                # Append count to destination
                most_recent['destination'] = f"{dest} x{count}"
                most_recent['_group_count'] = count

            grouped_entries.append(most_recent)

        # Sort grouped entries by timestamp (most recent first)
        grouped_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return grouped_entries

    def _show_traffic_context_menu(self, event):
        """Show context menu for traffic entries"""
        item = self.traffic_tree.identify_row(event.y)
        if not item:
            return

        self.traffic_tree.selection_set(item)
        values = self.traffic_tree.item(item, 'values')
        host = values[4]
        dest = values[3].split(':')[0] if ':' in values[3] else values[3]

        menu = tk.Menu(self.root, tearoff=0, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        menu.add_command(label="View Details", command=lambda: self._show_traffic_details(None))
        menu.add_command(label="Copy Host", command=lambda: self.copy_to_clipboard(host))
        menu.add_separator()
        if host:
            menu.add_command(label=f"VirusTotal: {host}",
                            command=lambda: self.lookup_virustotal(host))
        menu.add_command(label=f"VirusTotal: {dest}",
                        command=lambda: self.lookup_virustotal(dest))
        menu.add_separator()
        menu.add_command(label=f"Search Alerts for: {host[:30] if host else dest}",
                        command=lambda: [self.notebook.select(1), self.search_var.set(host if host else dest)])
        menu.post(event.x_root, event.y_root)

    def _show_traffic_details(self, event):
        """Show detailed traffic entry information"""
        selection = self.traffic_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.traffic_tree.item(item, 'values')
        timestamp, protocol, source = values[0], values[1], values[2]

        # Find raw data
        raw_data = None
        for entry in self.traffic_data:
            if entry['timestamp'] == timestamp and entry['protocol'] == protocol:
                raw_data = entry.get('raw_data', {})
                break

        if not raw_data:
            return

        # Create popup
        popup = tk.Toplevel(self.root)
        popup.title(f"{protocol} Connection Details")
        popup.geometry("650x500")
        popup.configure(bg=self.colors['bg'])

        # Header
        host = values[4] or values[3]
        ttk.Label(popup, text=f"󰖟 {protocol}: {host}",
                 font=('Hack Nerd Font', 12, 'bold')).pack(pady=10)

        # Connection info
        info_frame = ttk.LabelFrame(popup, text="Connection Details", padding="10")
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        conn_details = [
            ("Timestamp", timestamp),
            ("Protocol", protocol),
            ("Source", values[2]),
            ("Destination", values[3]),
            ("Host/SNI", values[4]),
        ]

        for i, (label, value) in enumerate(conn_details):
            ttk.Label(info_frame, text=f"{label}:").grid(row=i, column=0, sticky='w', padx=5)
            ttk.Label(info_frame, text=str(value)).grid(row=i, column=1, sticky='w', padx=5)

        # Protocol-specific details
        proto_data = raw_data.get(protocol.lower(), {})
        if proto_data:
            detail_frame = ttk.LabelFrame(popup, text=f"{protocol} Details", padding="10")
            detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            detail_text = self.widgets.create_textbox(detail_frame, height=12,
                                                      bg=self.colors['bg_alt'],
                                                      fg=self.colors['fg'],
                                                      font=('Hack Nerd Font', 9))
            detail_text.pack(fill=tk.BOTH, expand=True)

            if protocol == 'HTTP':
                detail_text.insert(tk.END, f"Method: {proto_data.get('http_method', 'N/A')}\n")
                detail_text.insert(tk.END, f"URL: {proto_data.get('url', 'N/A')}\n")
                detail_text.insert(tk.END, f"Status: {proto_data.get('status', 'N/A')}\n")
                detail_text.insert(tk.END, f"Content-Type: {proto_data.get('http_content_type', 'N/A')}\n")
                detail_text.insert(tk.END, f"User-Agent: {proto_data.get('http_user_agent', 'N/A')}\n")
                detail_text.insert(tk.END, f"Length: {proto_data.get('length', 'N/A')}\n")
                detail_text.insert(tk.END, f"Referrer: {proto_data.get('http_refer', 'N/A')}\n")

            elif protocol == 'TLS':
                detail_text.insert(tk.END, f"Version: {proto_data.get('version', 'N/A')}\n")
                detail_text.insert(tk.END, f"SNI: {proto_data.get('sni', 'N/A')}\n")
                detail_text.insert(tk.END, f"Subject: {proto_data.get('subject', 'N/A')}\n")
                detail_text.insert(tk.END, f"Issuer: {proto_data.get('issuerdn', 'N/A')}\n")
                detail_text.insert(tk.END, f"Fingerprint: {proto_data.get('fingerprint', 'N/A')}\n")
                ja3 = proto_data.get('ja3', {})
                if isinstance(ja3, dict):
                    detail_text.insert(tk.END, f"JA3 Hash: {ja3.get('hash', 'N/A')}\n")
                    detail_text.insert(tk.END, f"JA3 String: {ja3.get('string', 'N/A')}\n")

            elif protocol == 'SSH':
                client = proto_data.get('client', {})
                server = proto_data.get('server', {})
                if isinstance(client, dict):
                    detail_text.insert(tk.END, f"Client Proto: {client.get('proto_version', 'N/A')}\n")
                    detail_text.insert(tk.END, f"Client Software: {client.get('software_version', 'N/A')}\n")
                if isinstance(server, dict):
                    detail_text.insert(tk.END, f"Server Proto: {server.get('proto_version', 'N/A')}\n")
                    detail_text.insert(tk.END, f"Server Software: {server.get('software_version', 'N/A')}\n")

            else:
                # Generic JSON display
                detail_text.insert(tk.END, json.dumps(proto_data, indent=2))

        # Close button
        self.widgets.create_button(popup, text="Close",
                                   command=popup.destroy).pack(pady=10)

    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is a local/private address (127.x, 10.x, 192.168.x, 172.16-31.x)"""
        if not ip:
            return False
        # Localhost
        if ip.startswith('127.'):
            return True
        # Private Class A (10.0.0.0/8)
        if ip.startswith('10.'):
            return True
        # Private Class B (172.16.0.0/12)
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except:
                pass
        # Private Class C (192.168.0.0/16)
        if ip.startswith('192.168.'):
            return True
        # Link-local (169.254.0.0/16)
        if ip.startswith('169.254.'):
            return True
        return False

    def refresh_localhost(self):
        """Refresh local network traffic analysis from shared EVE buffer"""
        # Update the shared buffer first
        self._update_eve_buffer()

        # Build fresh counts and events from buffer
        port_activity = {}
        events = []

        for entry in self.eve_event_buffer:
            data = entry['data']
            ts = entry['timestamp']
            src = data.get('src_ip', '')
            dst = data.get('dest_ip', '')

            # Filter for local network traffic (localhost + private IPs)
            if src and (self._is_local_ip(src) or self._is_local_ip(dst)):
                event = data.get('event_type', '')
                src_port = data.get('src_port', '')
                dst_port = data.get('dest_port', '')

                event_line = f"[{ts}] {event.upper():6} {src}:{src_port} → {dst}:{dst_port}"
                events.append(event_line)

                # Count port activity
                if dst_port:
                    port_activity[dst_port] = port_activity.get(dst_port, 0) + 1

        # Update cache for reference
        self.localhost_cache = {
            'port_activity': port_activity,
            'events': [(datetime.now(), e) for e in events[-200:]],  # Keep last 200
            'last_update': datetime.now()
        }

        # Display data
        self.localhost_text.delete(1.0, tk.END)

        retention_info = f"Data retention: {self.data_retention_minutes} min"
        self.localhost_text.insert(tk.END, f"═══ Local Network Port Activity ({retention_info}) ═══\n\n")
        dev_ports = {22: 'SSH', 3389: 'RDP', 5432: 'PostgreSQL', 7474: 'Neo4j HTTP',
                    7687: 'Neo4j Bolt', 6788: 'Elastic', 6789: 'Elastic',
                    6791: 'Elastic', 8181: 'Filebeat', 631: 'CUPS'}
        for port, count in sorted(port_activity.items(), key=lambda x: -x[1])[:15]:
            name = dev_ports.get(port, '')
            self.localhost_text.insert(tk.END, f"  Port {port:5} ({name:12}): {count} events\n")

        self.localhost_text.insert(tk.END, f"\n═══ Recent Local Network Events (newest first) ═══\n\n")
        # Show newest first (reverse the list)
        for event_line in reversed(events[-50:]):
            self.localhost_text.insert(tk.END, f"  {event_line}\n")

    def refresh_dns(self):
        """Refresh DNS analysis from shared EVE buffer"""
        # Update the shared buffer first
        self._update_eve_buffer()

        # Get type filter
        type_filter = self.dns_type_filter.get()

        # Build DNS entries list
        dns_entries = []
        query_types = {}

        for entry in self.eve_event_buffer:
            data = entry['data']
            if data.get('event_type') == 'dns':
                dns = data.get('dns', {})
                rrname = dns.get('rrname', '')
                rrtype = dns.get('rrtype', 'A')
                rcode = dns.get('rcode', '')

                # Count query types
                if rrtype:
                    query_types[rrtype] = query_types.get(rrtype, 0) + 1

                # Apply type filter
                if type_filter != "all" and rrtype != type_filter:
                    continue

                # Extract answer from answers array or rdata
                answers = dns.get('answers', [])
                answer = ''
                if answers:
                    # Get first answer rdata
                    first_answer = answers[0] if isinstance(answers, list) else {}
                    answer = first_answer.get('rdata', '') if isinstance(first_answer, dict) else str(first_answer)
                else:
                    answer = dns.get('rdata', '')

                # Truncate answer if too long
                if len(answer) > 30:
                    answer = answer[:27] + '...'

                dns_entries.append({
                    'timestamp': entry['timestamp'],
                    'type': rrtype,
                    'domain': rrname,
                    'answer': answer,
                    'rcode': rcode,
                    'source': data.get('src_ip', ''),
                    'raw_data': data
                })

        # Update cache for reference
        self.dns_cache = {
            'query_types': query_types,
            'last_update': datetime.now()
        }

        # Sort by selected column
        sort_col = self.dns_sort_column
        dns_entries.sort(key=lambda x: x.get(sort_col, ''), reverse=self.dns_sort_reverse)

        # Apply grouping unless ungrouped view is selected
        if not self.dns_ungrouped.get():
            dns_entries = self._group_dns_by_domain(dns_entries)

        # Limit to 300 entries for performance
        dns_entries = dns_entries[:300]

        # Update stats label
        total = len(dns_entries)
        type_breakdown = ', '.join(f"{t}: {c}" for t, c in sorted(query_types.items(), key=lambda x: -x[1])[:4])
        self.dns_stats_label.configure(text=f"{total} queries | {type_breakdown}")

        # Build list of new values tuples for comparison
        new_values = []
        for entry in dns_entries:
            new_values.append((
                entry['timestamp'],
                entry['type'],
                entry['domain'],
                entry['answer'],
                entry['rcode'],
                entry['source']
            ))

        # Get current treeview values
        current_items = self.dns_tree.get_children()
        current_values = [self.dns_tree.item(item, 'values') for item in current_items]

        # Compare - only update if data changed (silent refresh)
        if new_values == current_values:
            self.dns_data = dns_entries
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.dns_tree.yview()
        selected = self.dns_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.dns_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate treeview
        for item in current_items:
            self.dns_tree.delete(item)

        self.dns_data = dns_entries

        for entry in dns_entries:
            rcode = entry['rcode']
            if rcode in ('SERVFAIL', 'REFUSED'):
                tag = 'error'
            elif rcode == 'NXDOMAIN':
                tag = 'nxdomain'
            else:
                tag = ''

            self.dns_tree.insert('', tk.END, values=(
                entry['timestamp'],
                entry['type'],
                entry['domain'],
                entry['answer'],
                entry['rcode'],
                entry['source']
            ), tags=(tag,) if tag else ())

        # Restore scroll position
        self.dns_tree.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.dns_tree.get_children():
                if self.dns_tree.item(item, 'values') == selected_values:
                    self.dns_tree.selection_set(item)
                    break

    def sort_dns(self, column):
        """Sort DNS by column"""
        if self.dns_sort_column == column:
            self.dns_sort_reverse = not self.dns_sort_reverse
        else:
            self.dns_sort_column = column
            self.dns_sort_reverse = True
        self.refresh_dns()

    def _toggle_dns_grouping(self):
        """Toggle between grouped and ungrouped DNS view"""
        current = self.dns_ungrouped.get()
        self.dns_ungrouped.set(not current)

        if self.dns_ungrouped.get():
            self.dns_ungroup_btn.configure(text="󰘸 Group")
        else:
            self.dns_ungroup_btn.configure(text="󰘷 Ungroup")

        self.refresh_dns()

    def _group_dns_by_domain(self, entries: list) -> list:
        """Group DNS entries by domain, appending x{count} for duplicates."""
        if not entries:
            return entries

        # Group by domain
        domain_groups = {}
        for entry in entries:
            domain = entry.get('domain', '')
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(entry)

        # Build grouped result
        grouped_entries = []
        for domain, group in domain_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['domain'] = f"{domain} x{count}"
                most_recent['_group_count'] = count

            grouped_entries.append(most_recent)

        grouped_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped_entries

    def _show_dns_context_menu(self, event):
        """Show context menu for DNS entries"""
        item = self.dns_tree.identify_row(event.y)
        if not item:
            return

        self.dns_tree.selection_set(item)
        values = self.dns_tree.item(item, 'values')
        domain = values[2]
        source_ip = values[5]

        menu = tk.Menu(self.root, tearoff=0, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        menu.add_command(label="View Details", command=lambda: self._show_dns_details(None))
        menu.add_command(label="Copy Domain", command=lambda: self.copy_to_clipboard(domain))
        menu.add_separator()
        menu.add_command(label=f"Search Alerts for: {domain[:30]}",
                        command=lambda: [self.notebook.select(1), self.search_var.set(domain)])
        menu.add_command(label=f"VirusTotal: {domain}",
                        command=lambda: self.lookup_virustotal(domain))
        if source_ip:
            menu.add_command(label=f"VirusTotal: {source_ip}",
                            command=lambda: self.lookup_virustotal(source_ip))
        menu.post(event.x_root, event.y_root)

    def _show_dns_details(self, event):
        """Show detailed DNS entry information"""
        selection = self.dns_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.dns_tree.item(item, 'values')
        timestamp, qtype, domain = values[0], values[1], values[2]

        # Find raw data
        raw_data = None
        for entry in self.dns_data:
            if entry['timestamp'] == timestamp and entry['domain'] == domain:
                raw_data = entry.get('raw_data', {})
                break

        if not raw_data:
            return

        # Create popup
        popup = tk.Toplevel(self.root)
        popup.title(f"DNS Query - {domain}")
        popup.geometry("600x450")
        popup.configure(bg=self.colors['bg'])

        # Header
        ttk.Label(popup, text=f"󰇖 {qtype} Query: {domain}",
                 font=('Hack Nerd Font', 12, 'bold')).pack(pady=10)

        # Info frame
        info_frame = ttk.LabelFrame(popup, text="Query Details", padding="10")
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        dns_data = raw_data.get('dns', {})
        details = [
            ("Timestamp", timestamp),
            ("Query Type", qtype),
            ("Domain", domain),
            ("Response Code", dns_data.get('rcode', 'N/A')),
            ("Source IP", raw_data.get('src_ip', 'N/A')),
            ("Dest IP", raw_data.get('dest_ip', 'N/A')),
            ("TTL", dns_data.get('ttl', 'N/A')),
        ]

        for i, (label, value) in enumerate(details):
            ttk.Label(info_frame, text=f"{label}:").grid(row=i, column=0, sticky='w', padx=5)
            ttk.Label(info_frame, text=str(value)).grid(row=i, column=1, sticky='w', padx=5)

        # Answers section
        answers = dns_data.get('answers', [])
        if answers:
            ans_frame = ttk.LabelFrame(popup, text=f"Answers ({len(answers)})", padding="10")
            ans_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            ans_text = self.widgets.create_textbox(ans_frame, height=8,
                                                   bg=self.colors['bg_alt'],
                                                   fg=self.colors['fg'],
                                                   font=('Hack Nerd Font', 9))
            ans_text.pack(fill=tk.BOTH, expand=True)

            for ans in answers:
                if isinstance(ans, dict):
                    rdata = ans.get('rdata', 'N/A')
                    rtype = ans.get('rrtype', '')
                    ttl = ans.get('ttl', '')
                    ans_text.insert(tk.END, f"  {rtype:8} TTL={ttl:6} → {rdata}\n")
                else:
                    ans_text.insert(tk.END, f"  {ans}\n")

        # Close button
        self.widgets.create_button(popup, text="Close",
                                   command=popup.destroy).pack(pady=10)

    def refresh_all(self):
        def do_refresh():
            self.refresh_status()
            self.refresh_stats()
            self.refresh_activity()
            self.refresh_clamav_stats()

            # Refresh active tab
            current = self.notebook.index(self.notebook.select())
            if current == 1:
                self.refresh_alerts()
            elif current == 2:
                self.refresh_traffic()
            elif current == 3:
                self.refresh_localhost()
            elif current == 4:
                self.refresh_dns()
            elif current == 5:
                self.refresh_clamav_overview()
            elif current == 6:
                self.refresh_quarantine()

        threading.Thread(target=do_refresh, daemon=True).start()

    def _initial_data_load(self):
        """Perform initial data load for all tabs on startup.

        This runs once at startup to populate all tabs with data,
        rather than waiting for user to manually refresh each tab.
        """
        def do_initial_load():
            try:
                # Load EVE buffer first (this populates the shared data)
                self._update_eve_buffer()

                # Schedule UI updates on main thread
                self.root.after(0, self._populate_initial_tabs)
            except Exception as e:
                print(f"Initial data load error: {e}")

        threading.Thread(target=do_initial_load, daemon=True).start()

    def _populate_initial_tabs(self):
        """Populate all tabs with initial data (runs on main thread)"""
        try:
            # Overview tab
            self.refresh_stats()
            self.refresh_activity()

            # Alerts tab
            self.refresh_alerts()

            # Traffic tab
            self.refresh_traffic()

            # Localhost tab
            self.refresh_localhost()

            # DNS tab
            self.refresh_dns()

            # ClamAV tabs
            self.refresh_clamav_stats()
            self.refresh_clamav_overview()
            self.refresh_quarantine()

            # Analytics (if matplotlib available)
            if MATPLOTLIB_AVAILABLE:
                try:
                    self.refresh_analytics()
                except:
                    pass

            # Security tabs
            self.refresh_connections()
            self.refresh_logs()
            self.refresh_firewall()

        except Exception as e:
            print(f"Error populating initial tabs: {e}")

    def start_auto_refresh(self):
        if self.auto_refresh.get():
            self.refresh_all()
        self.root.after(self.refresh_interval, self.start_auto_refresh)

    # Suricata control methods
    def start_ids(self):
        def do_start():
            result = subprocess.run(["pkexec", "systemctl", "start", "suricata-laptop"],
                                   capture_output=True, text=True, timeout=30)
            self.root.after(100, self.refresh_status)
            if result.returncode == 0:
                self.root.after(100, lambda: messagebox.showinfo("Success", "IDS started successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error", f"Failed to start IDS: {result.stderr}"))

        threading.Thread(target=do_start, daemon=True).start()

    def stop_ids(self):
        def do_stop():
            result = subprocess.run(["pkexec", "systemctl", "stop", "suricata-laptop"],
                                   capture_output=True, text=True, timeout=30)
            self.root.after(100, self.refresh_status)
            if result.returncode == 0:
                self.root.after(100, lambda: messagebox.showinfo("Success", "IDS stopped successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error", f"Failed to stop IDS: {result.stderr}"))

        threading.Thread(target=do_stop, daemon=True).start()

    def update_rules(self):
        def do_update():
            result = subprocess.run(["pkexec", "suricata-update", "--no-test"],
                                   capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                self.root.after(100, lambda: messagebox.showinfo("Success", "Rules updated successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error", f"Failed to update rules: {result.stderr}"))

        threading.Thread(target=do_update, daemon=True).start()
        messagebox.showinfo("Updating", "Updating rules in background...")

    def clean_logs(self):
        result = subprocess.run(["pkexec", "/usr/local/bin/ids-cleanup"],
                               capture_output=True, text=True, timeout=30)
        messagebox.showinfo("Cleanup", result.stdout or "Logs cleaned")

    def open_config(self):
        subprocess.Popen(["xdg-open", "/etc/suricata/suricata.yaml"])

    def view_logs(self):
        subprocess.Popen(["xdg-open", "/var/log/suricata/"])

    # ClamAV control methods - using batched privilege escalation
    def start_clamav(self):
        def do_start():
            # Single auth prompt for all 3 services
            result = run_privileged_batch([
                "systemctl start clamav-daemon",
                "systemctl start clamav-freshclam",
                "systemctl start clamav-clamonacc",
            ])
            self.root.after(100, self.refresh_status)
            self.root.after(200, self.refresh_clamav_stats)  # Update top stats bar
            if result.success:
                self.root.after(100, lambda: messagebox.showinfo("Success", "ClamAV started successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error", f"Failed to start ClamAV: {result.message}"))

        threading.Thread(target=do_start, daemon=True).start()

    def stop_clamav(self):
        def do_stop():
            # Single auth prompt for all 3 services (reverse order)
            result = run_privileged_batch([
                "systemctl stop clamav-clamonacc",
                "systemctl stop clamav-freshclam",
                "systemctl stop clamav-daemon",
            ])
            self.root.after(100, self.refresh_status)
            self.root.after(200, self.refresh_clamav_stats)  # Update top stats bar
            if result.success:
                self.root.after(100, lambda: messagebox.showinfo("Success", "ClamAV stopped successfully"))
            else:
                self.root.after(100, lambda: messagebox.showerror("Error", f"Failed to stop ClamAV: {result.message}"))

        threading.Thread(target=do_stop, daemon=True).start()

    def update_signatures(self):
        """Manually update ClamAV virus signatures"""
        self.show_progress("Updating virus signatures...")

        def do_update():
            try:
                # Single auth prompt: stop freshclam, update, restart
                result = run_privileged_batch([
                    "systemctl stop clamav-freshclam",
                    "freshclam",
                    "systemctl start clamav-freshclam",
                ])

                def show_result():
                    self.hide_progress()
                    if result.success:
                        # Refresh the signature info display and stats bar
                        self.load_clamav_settings()
                        self.refresh_clamav_stats()  # Update top stats bar
                        messagebox.showinfo("Success", "Virus signatures updated successfully!\n\nSignature info will refresh shortly.")
                    else:
                        messagebox.showerror("Error", f"Update failed: {result.message}")

                self.root.after(100, show_result)

            except Exception as e:
                self.root.after(100, self.hide_progress)
                self.root.after(100, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_update, daemon=True).start()

    def clean_av_logs(self):
        result = subprocess.run(["pkexec", "/usr/local/bin/av-cleanup"],
                               capture_output=True, text=True, timeout=30)
        messagebox.showinfo("Cleanup", result.stdout or "AV logs cleaned")

    def view_av_logs(self):
        subprocess.Popen(["xdg-open", "/var/log/clamav/"])

    def deploy_suricata(self):
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suricata_deploy.sh")
        if os.path.exists(script_path):
            subprocess.Popen(["pkexec", "bash", script_path, "--suricata"])
            messagebox.showinfo("Deploying", "Suricata deployment started in terminal...")
        else:
            messagebox.showerror("Error", f"Deploy script not found: {script_path}")

    def deploy_clamav(self):
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suricata_deploy.sh")
        if os.path.exists(script_path):
            subprocess.Popen(["pkexec", "bash", script_path, "--clamav"])
            messagebox.showinfo("Deploying", "ClamAV deployment started in terminal...")
        else:
            messagebox.showerror("Error", f"Deploy script not found: {script_path}")

    # ClamAV refresh methods
    def refresh_clamav_stats(self):
        """Refresh ClamAV dashboard stats (uses centralized status cache).

        Service status (daemon, freshclam, onaccess) is handled by refresh_status().
        This function only updates signature count and quarantine count.
        """
        try:
            # Service status is now handled by refresh_status() - just refresh cache and update
            self.refresh_status()

            # Signature count - check both .cvd and .cld files
            sig_count = "N/A"
            try:
                # Iterate files in Python and sum signatures
                import glob
                total_sigs = 0
                for pattern in ['/var/lib/clamav/*.cld', '/var/lib/clamav/*.cvd']:
                    for fpath in glob.glob(pattern):
                        result = subprocess.run(
                            ["sigtool", "--info", fpath],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.stdout:
                            # Parse "Number of signatures: XXXX"
                            for line in result.stdout.split('\n'):
                                if 'Number of signatures' in line:
                                    parts = line.split(':')
                                    if len(parts) == 2:
                                        try:
                                            count = int(parts[1].strip())
                                            total_sigs += count
                                        except ValueError:
                                            pass
                if total_sigs > 0:
                    sig_count = str(total_sigs)
            except:
                pass
            self.clamav_stat_widgets['signatures'].configure(text=sig_count)

            # Quarantine count
            quarantine_count = 0
            quarantine_dir = "/var/lib/clamav/quarantine"
            if os.path.exists(quarantine_dir):
                try:
                    quarantine_count = len([f for f in os.listdir(quarantine_dir) if os.path.isfile(os.path.join(quarantine_dir, f))])
                except:
                    pass
            self.clamav_stat_widgets['quarantine'].configure(
                text=str(quarantine_count),
                fg=self.colors['red'] if quarantine_count > 0 else self.colors['green']
            )

        except Exception as e:
            print(f"Error refreshing ClamAV stats: {e}")

    def refresh_clamav_overview(self):
        try:
            self.clamav_info_text.delete(1.0, tk.END)

            # Last scan info
            self.clamav_info_text.insert(tk.END, "═══ Scan Information ═══\n\n")

            # Daily scan
            daily_log = "/var/log/clamav/daily-scan.log"
            if os.path.exists(daily_log):
                result = subprocess.run(["tail", "-20", daily_log], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[-10:]:
                        if 'Infected files' in line or 'Scanned files' in line or 'Started' in line or 'Completed' in line:
                            self.clamav_info_text.insert(tk.END, f"  {line}\n")
            else:
                self.clamav_info_text.insert(tk.END, "  No daily scan logs yet\n")

            # Signature info
            self.clamav_info_text.insert(tk.END, "\n═══ Signature Database ═══\n\n")
            try:
                # Check for .cld or .cvd files
                sig_files = []
                for ext in ['cld', 'cvd']:
                    daily_path = f"/var/lib/clamav/daily.{ext}"
                    if os.path.exists(daily_path):
                        sig_files.append(daily_path)
                        break

                if sig_files:
                    result = subprocess.run(
                        ["sigtool", "--info", sig_files[0]],
                        capture_output=True, text=True, timeout=5
                    )
                    # Filter output in Python instead of using grep
                    if result.stdout:
                        filtered_lines = [line for line in result.stdout.split('\n')
                                        if 'Build time' in line or 'Number of signatures' in line]
                        result.stdout = '\n'.join(filtered_lines)
                    if result.stdout:
                        for line in result.stdout.strip().split('\n'):
                            self.clamav_info_text.insert(tk.END, f"  {line}\n")
                    else:
                        self.clamav_info_text.insert(tk.END, "  Signature database loaded\n")
                else:
                    self.clamav_info_text.insert(tk.END, "  No signature database found\n")
            except:
                self.clamav_info_text.insert(tk.END, "  Unable to get signature info\n")

            # Recent detections - check multiple log sources
            self.clamav_detect_text.delete(1.0, tk.END)
            found_detections = False

            # Check quarantine log first
            quarantine_log = "/var/log/clamav/quarantine.log"
            if os.path.exists(quarantine_log):
                try:
                    result = subprocess.run(["tail", "-30", quarantine_log], capture_output=True, text=True, timeout=5)
                    if result.stdout.strip():
                        for line in result.stdout.strip().split('\n'):
                            if 'DETECTED' in line or 'FOUND' in line:
                                self.clamav_detect_text.insert(tk.END, f"{line}\n", 'threat')
                                found_detections = True
                            elif line.strip():
                                self.clamav_detect_text.insert(tk.END, f"{line}\n", 'info')
                except:
                    pass

            # Also check clamd.log for FOUND entries
            clamd_log = "/var/log/clamav/clamd.log"
            if os.path.exists(clamd_log):
                try:
                    # Read file and filter in Python for safety
                    with open(clamd_log, 'r') as f:
                        lines = f.readlines()
                        found_lines = [line for line in lines if 'FOUND' in line.upper()][-20:]
                    result = type('obj', (object,), {'stdout': ''.join(found_lines), 'returncode': 0})()
                    if result.stdout.strip():
                        if not found_detections:
                            self.clamav_detect_text.insert(tk.END, "═══ Clamd Detections ═══\n\n", 'info')
                        for line in result.stdout.strip().split('\n'):
                            self.clamav_detect_text.insert(tk.END, f"{line}\n", 'threat')
                            found_detections = True
                except:
                    pass

            # Check user scan logs
            user_scan_log = os.path.expanduser("~/.local/state/clamav-scans.log")
            if os.path.exists(user_scan_log):
                try:
                    # Read file and filter in Python for safety
                    with open(user_scan_log, 'r') as f:
                        lines = f.readlines()
                        found_lines = [line for line in lines
                                     if 'FOUND' in line.upper() or 'infected' in line.lower()][-10:]
                    result = type('obj', (object,), {'stdout': ''.join(found_lines), 'returncode': 0})()
                    if result.stdout.strip():
                        if not found_detections:
                            self.clamav_detect_text.insert(tk.END, "═══ User Scan Detections ═══\n\n", 'info')
                        for line in result.stdout.strip().split('\n'):
                            self.clamav_detect_text.insert(tk.END, f"{line}\n", 'threat')
                            found_detections = True
                except:
                    pass

            if not found_detections:
                self.clamav_detect_text.insert(tk.END, "No threats detected - System clean!\n", 'info')

        except Exception as e:
            self.clamav_info_text.insert(tk.END, f"Error: {e}\n")

    def refresh_quarantine(self):
        try:
            quarantine_dir = "/var/lib/clamav/quarantine"
            metadata_file = os.path.join(quarantine_dir, ".metadata.json")

            if not os.path.exists(quarantine_dir):
                return

            # Load metadata if exists
            metadata = {}
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                except:
                    pass

            files = []
            try:
                for f in os.listdir(quarantine_dir):
                    if f.startswith('.'):
                        continue
                    fpath = os.path.join(quarantine_dir, f)
                    if os.path.isfile(fpath):
                        stat = os.stat(fpath)
                        original_path = metadata.get(f, {}).get('original_path', 'Unknown')
                        files.append({
                            'filename': f,
                            'mtime': stat.st_mtime,
                            'size': stat.st_size,
                            'original_path': original_path,
                            'full_path': fpath
                        })
            except PermissionError:
                return

            # Add date_str for proper sorting
            for file_info in files:
                file_info['date'] = datetime.fromtimestamp(file_info['mtime']).strftime('%Y-%m-%d %H:%M')
                file_info['size_str'] = f"{file_info['size'] / 1024:.1f}KB" if file_info['size'] > 1024 else f"{file_info['size']}B"

            # Sort by selected column
            sort_col = self.quarantine_sort_column
            if sort_col == 'date':
                files.sort(key=lambda x: x['mtime'], reverse=self.quarantine_sort_reverse)
            elif sort_col == 'size':
                files.sort(key=lambda x: x['size'], reverse=self.quarantine_sort_reverse)
            else:
                files.sort(key=lambda x: x.get(sort_col, ''), reverse=self.quarantine_sort_reverse)

            # Build list of new values tuples for comparison
            new_values = []
            for file_info in files:
                new_values.append((
                    file_info['date'],
                    file_info['filename'],
                    file_info['size_str'],
                    file_info['original_path']
                ))

            # Get current treeview values
            current_items = self.quarantine_tree.get_children()
            current_values = [self.quarantine_tree.item(item, 'values') for item in current_items]

            # Compare - only update if data changed (silent refresh)
            if new_values == current_values:
                return

            # Data changed - save scroll position and selection
            scroll_pos = self.quarantine_tree.yview()
            selected = self.quarantine_tree.selection()
            selected_values = None
            if selected:
                try:
                    selected_values = self.quarantine_tree.item(selected[0], 'values')
                except:
                    pass

            # Clear existing items
            for item in current_items:
                self.quarantine_tree.delete(item)

            self.quarantine_data = {}
            for file_info in files:
                item_id = self.quarantine_tree.insert('', tk.END, values=(
                    file_info['date'],
                    file_info['filename'],
                    file_info['size_str'],
                    file_info['original_path']
                ))
                self.quarantine_data[item_id] = file_info

            # Restore scroll position
            self.quarantine_tree.yview_moveto(scroll_pos[0])

            # Restore selection if the same item still exists
            if selected_values:
                for item in self.quarantine_tree.get_children():
                    if self.quarantine_tree.item(item, 'values') == selected_values:
                        self.quarantine_tree.selection_set(item)
                        break

        except Exception as e:
            print(f"Error refreshing quarantine: {e}")

    def sort_quarantine(self, column):
        """Sort quarantine by column"""
        if self.quarantine_sort_column == column:
            self.quarantine_sort_reverse = not self.quarantine_sort_reverse
        else:
            self.quarantine_sort_column = column
            self.quarantine_sort_reverse = True
        self.refresh_quarantine()

    def clean_quarantine(self):
        if not messagebox.askyesno("Confirm", "Permanently delete ALL quarantined files?"):
            return
        result = subprocess.run(["pkexec", "/usr/local/bin/av-cleanup"],
                               capture_output=True, text=True, timeout=30)
        messagebox.showinfo("Cleanup", result.stdout or "Quarantine cleaned")
        self.refresh_quarantine()

    def delete_quarantine_file(self):
        """Delete selected file from quarantine"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Delete", "No file selected")
            return

        item = selection[0]
        file_info = self.quarantine_data.get(item)
        if not file_info:
            return

        if not messagebox.askyesno("Confirm Delete",
                                   f"Permanently delete '{file_info['filename']}'?\n\nThis cannot be undone."):
            return

        try:
            # Validate file path before deletion
            file_path = file_info['full_path']
            valid, err = validate_file_path(file_path, must_exist=True,
                                          allowed_dirs=["/var/lib/clamav/quarantine", "/var/quarantine"])
            if not valid:
                messagebox.showerror("Validation Error", err)
                return

            result = subprocess.run(["pkexec", "rm", "-f", file_path],
                                   capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                messagebox.showinfo("Deleted", f"File deleted: {file_info['filename']}")
                self.refresh_quarantine()
            else:
                messagebox.showerror("Error", f"Failed to delete: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def restore_quarantine_file(self):
        """Restore selected file from quarantine"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Restore", "No file selected")
            return

        item = selection[0]
        file_info = self.quarantine_data.get(item)
        if not file_info:
            return

        original_path = file_info.get('original_path', 'Unknown')
        if original_path == 'Unknown':
            # Ask for destination
            dest_path = filedialog.asksaveasfilename(
                title="Choose restore location",
                initialfile=file_info['filename'],
                initialdir=os.path.expanduser("~")
            )
            if not dest_path:
                return
        else:
            if not messagebox.askyesno("Confirm Restore",
                                       f"Restore '{file_info['filename']}' to:\n{original_path}\n\n"
                                       "WARNING: This file was quarantined as a potential threat!"):
                return
            dest_path = original_path

        try:
            # Validate source file path before restore
            source_path = file_info['full_path']
            valid, err = validate_file_path(source_path, must_exist=True,
                                          allowed_dirs=["/var/lib/clamav/quarantine", "/var/quarantine"])
            if not valid:
                messagebox.showerror("Validation Error", err)
                return

            # Validate destination path
            valid, err = validate_file_path(dest_path, must_exist=False)
            if not valid:
                messagebox.showerror("Validation Error", err)
                return

            result = subprocess.run(["pkexec", "mv", source_path, dest_path],
                                   capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                messagebox.showinfo("Restored", f"File restored to: {dest_path}")
                self.refresh_quarantine()
            else:
                messagebox.showerror("Error", f"Failed to restore: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_quarantine_context_menu(self, event):
        """Show context menu for quarantine"""
        item = self.quarantine_tree.identify_row(event.y)
        if not item:
            return

        self.quarantine_tree.selection_set(item)
        file_info = self.quarantine_data.get(item)
        if not file_info:
            return

        menu = tk.Menu(self.root, tearoff=0, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        menu.add_command(label="Restore File", command=self.restore_quarantine_file)
        menu.add_command(label="Delete Permanently", command=self.delete_quarantine_file)
        menu.add_separator()
        menu.add_command(label=f"Copy Path: {file_info['original_path'][:50]}",
                        command=lambda: self.copy_to_clipboard(file_info['original_path']))

        menu.post(event.x_root, event.y_root)

    # Scan methods
    def browse_scan_path(self):
        path = filedialog.askdirectory(initialdir=os.path.expanduser("~"))
        if path:
            self.scan_path_var.set(path)

    def start_custom_scan(self):
        path = self.scan_path_var.get()
        if path and os.path.exists(path):
            self.start_scan(path)
        else:
            messagebox.showerror("Error", "Invalid path")

    def start_scan(self, path):
        self.scan_cancelled = False

        def do_scan():
            self.root.after(0, lambda: self.scan_btn.configure(state='disabled'))
            self.root.after(0, lambda: self.cancel_scan_btn.configure(state='normal'))
            self.root.after(0, lambda: self.scan_status_label.configure(text="Scanning..."))
            self.root.after(0, lambda: self.show_progress("Scanning..."))
            self.root.after(0, lambda: self.scan_output_text.delete(1.0, tk.END))
            self.root.after(0, lambda: self.scan_output_text.insert(tk.END, f"Scanning: {path}\n\n", 'info'))

            try:
                # Validate scan path before scanning
                valid, err = validate_file_path(path, must_exist=True)
                if not valid:
                    self.root.after(0, lambda: messagebox.showerror("Validation Error", err))
                    self.root.after(0, lambda: self.scan_btn.configure(state='normal'))
                    self.root.after(0, lambda: self.cancel_scan_btn.configure(state='disabled'))
                    return

                self.scan_process = subprocess.Popen(
                    ["clamscan", "--infected", "--recursive", path],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )

                infected_count = 0
                for line in iter(self.scan_process.stdout.readline, ''):
                    if self.scan_cancelled:
                        break
                    if not line:
                        break

                    # Update UI from main thread
                    def update_output(l=line):
                        if 'FOUND' in l:
                            self.scan_output_text.insert(tk.END, l, 'infected')
                        elif 'Infected files:' in l or 'Scanned' in l:
                            self.scan_output_text.insert(tk.END, l, 'info')
                        else:
                            self.scan_output_text.insert(tk.END, l)
                        self.scan_output_text.see(tk.END)

                    self.root.after(0, update_output)

                    if 'FOUND' in line:
                        infected_count += 1

                self.scan_process.wait()

                def finish_scan():
                    self.scan_btn.configure(state='normal')
                    self.cancel_scan_btn.configure(state='disabled')
                    self.hide_progress()
                    self.scan_process = None

                    if self.scan_cancelled:
                        self.scan_status_label.configure(text="Scan cancelled")
                        self.scan_output_text.insert(tk.END, "\n󰅖 Scan cancelled by user\n", 'info')
                    elif infected_count > 0:
                        self.scan_status_label.configure(text=f"Found {infected_count} threat(s)!")
                        self.scan_output_text.insert(tk.END, f"\n⚠ {infected_count} threat(s) detected!\n", 'infected')
                    else:
                        self.scan_status_label.configure(text="Scan complete - Clean")
                        self.scan_output_text.insert(tk.END, "\n✓ No threats found\n", 'clean')

                self.root.after(0, finish_scan)

            except Exception as e:
                error_msg = str(e)
                def show_error(msg=error_msg):
                    self.scan_btn.configure(state='normal')
                    self.cancel_scan_btn.configure(state='disabled')
                    self.hide_progress()
                    self.scan_status_label.configure(text="Scan failed")
                    self.scan_output_text.insert(tk.END, f"\nError: {msg}\n", 'infected')
                    self.scan_process = None

                self.root.after(0, show_error)

        threading.Thread(target=do_scan, daemon=True).start()

    def cancel_scan(self):
        """Cancel running scan"""
        if self.scan_process:
            self.scan_cancelled = True
            try:
                self.scan_process.terminate()
                self.scan_process.wait(timeout=5)
            except:
                try:
                    self.scan_process.kill()
                except:
                    pass

