"""
UI Components for Security Suite Control Panel

This package contains reusable UI components extracted from main_window.py
to eliminate code duplication and improve maintainability.

Components:
    TreeviewBuilder: Creates Treeview widgets with standard patterns
    TreeviewWrapper: Wrapper for Treeview with common operations
    AsyncRunner: Manages background thread operations safely
"""

from ids_suite.ui.components.treeview_builder import (
    TreeviewBuilder,
    TreeviewWrapper,
    create_standard_alerts_tree,
    create_standard_traffic_tree,
    create_standard_dns_tree,
)
from ids_suite.ui.components.async_runner import AsyncRunner, async_method

__all__ = [
    'TreeviewBuilder',
    'TreeviewWrapper',
    'create_standard_alerts_tree',
    'create_standard_traffic_tree',
    'create_standard_dns_tree',
    'AsyncRunner',
    'async_method',
]
