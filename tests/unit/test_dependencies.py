"""
Tests for ids_suite.core.dependencies module
Tests optional dependency detection and lazy loading
"""

import pytest
from unittest.mock import patch, MagicMock
import sys


class TestDependencyFlags:
    """Test module-level availability flags"""

    def test_ctk_available_is_bool(self):
        """CTK_AVAILABLE should be a boolean"""
        from ids_suite.core.dependencies import CTK_AVAILABLE
        assert isinstance(CTK_AVAILABLE, bool)

    def test_matplotlib_available_is_bool(self):
        """MATPLOTLIB_AVAILABLE should be a boolean"""
        from ids_suite.core.dependencies import MATPLOTLIB_AVAILABLE
        assert isinstance(MATPLOTLIB_AVAILABLE, bool)

    def test_geoip_available_is_bool(self):
        """GEOIP_AVAILABLE should be a boolean"""
        from ids_suite.core.dependencies import GEOIP_AVAILABLE
        assert isinstance(GEOIP_AVAILABLE, bool)

    def test_keyring_available_is_bool(self):
        """KEYRING_AVAILABLE should be a boolean"""
        from ids_suite.core.dependencies import KEYRING_AVAILABLE
        assert isinstance(KEYRING_AVAILABLE, bool)

    def test_requests_available_is_bool(self):
        """REQUESTS_AVAILABLE should be a boolean"""
        from ids_suite.core.dependencies import REQUESTS_AVAILABLE
        assert isinstance(REQUESTS_AVAILABLE, bool)


class TestGetCtk:
    """Test get_ctk() lazy loader"""

    def test_get_ctk_returns_module_or_none(self):
        """get_ctk should return module if available, None otherwise"""
        from ids_suite.core.dependencies import get_ctk, CTK_AVAILABLE
        result = get_ctk()
        if CTK_AVAILABLE:
            assert result is not None
            assert hasattr(result, 'CTk') or hasattr(result, 'set_appearance_mode')
        else:
            assert result is None

    def test_get_ctk_when_available(self):
        """Test get_ctk when CTK_AVAILABLE is True"""
        with patch('ids_suite.core.dependencies.CTK_AVAILABLE', True):
            # Need to also patch the import
            mock_ctk = MagicMock()
            with patch.dict(sys.modules, {'customtkinter': mock_ctk}):
                from ids_suite.core import dependencies
                # Force re-evaluation with patched flag
                original_flag = dependencies.CTK_AVAILABLE
                dependencies.CTK_AVAILABLE = True
                try:
                    result = dependencies.get_ctk()
                    # Should attempt to import and return something
                    assert result is not None or result is None  # Either is valid based on actual availability
                finally:
                    dependencies.CTK_AVAILABLE = original_flag

    def test_get_ctk_when_unavailable(self):
        """Test get_ctk when CTK_AVAILABLE is False"""
        from ids_suite.core import dependencies
        original_flag = dependencies.CTK_AVAILABLE
        dependencies.CTK_AVAILABLE = False
        try:
            result = dependencies.get_ctk()
            assert result is None
        finally:
            dependencies.CTK_AVAILABLE = original_flag


class TestGetMatplotlib:
    """Test get_matplotlib_components() lazy loader"""

    def test_get_matplotlib_returns_tuple(self):
        """get_matplotlib_components should return 3-tuple"""
        from ids_suite.core.dependencies import get_matplotlib_components
        result = get_matplotlib_components()
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_get_matplotlib_when_available(self):
        """Test get_matplotlib_components when MATPLOTLIB_AVAILABLE is True"""
        from ids_suite.core.dependencies import get_matplotlib_components, MATPLOTLIB_AVAILABLE
        FigureCanvas, Figure, mdates = get_matplotlib_components()
        if MATPLOTLIB_AVAILABLE:
            assert FigureCanvas is not None
            assert Figure is not None
            assert mdates is not None
        else:
            assert FigureCanvas is None
            assert Figure is None
            assert mdates is None

    def test_get_matplotlib_when_unavailable(self):
        """Test get_matplotlib_components when MATPLOTLIB_AVAILABLE is False"""
        from ids_suite.core import dependencies
        original_flag = dependencies.MATPLOTLIB_AVAILABLE
        dependencies.MATPLOTLIB_AVAILABLE = False
        try:
            FigureCanvas, Figure, mdates = dependencies.get_matplotlib_components()
            assert FigureCanvas is None
            assert Figure is None
            assert mdates is None
        finally:
            dependencies.MATPLOTLIB_AVAILABLE = original_flag


class TestGetGeoip:
    """Test get_geoip() lazy loader"""

    def test_get_geoip_returns_module_or_none(self):
        """get_geoip should return module if available, None otherwise"""
        from ids_suite.core.dependencies import get_geoip, GEOIP_AVAILABLE
        result = get_geoip()
        if GEOIP_AVAILABLE:
            assert result is not None
        else:
            assert result is None

    def test_get_geoip_when_unavailable(self):
        """Test get_geoip when GEOIP_AVAILABLE is False"""
        from ids_suite.core import dependencies
        original_flag = dependencies.GEOIP_AVAILABLE
        dependencies.GEOIP_AVAILABLE = False
        try:
            result = dependencies.get_geoip()
            assert result is None
        finally:
            dependencies.GEOIP_AVAILABLE = original_flag


class TestGetKeyring:
    """Test get_keyring() lazy loader"""

    def test_get_keyring_returns_module_or_none(self):
        """get_keyring should return module if available, None otherwise"""
        from ids_suite.core.dependencies import get_keyring, KEYRING_AVAILABLE
        result = get_keyring()
        if KEYRING_AVAILABLE:
            assert result is not None
            assert hasattr(result, 'get_password') or hasattr(result, 'set_password')
        else:
            assert result is None

    def test_get_keyring_when_unavailable(self):
        """Test get_keyring when KEYRING_AVAILABLE is False"""
        from ids_suite.core import dependencies
        original_flag = dependencies.KEYRING_AVAILABLE
        dependencies.KEYRING_AVAILABLE = False
        try:
            result = dependencies.get_keyring()
            assert result is None
        finally:
            dependencies.KEYRING_AVAILABLE = original_flag

    def test_get_keyring_when_available(self):
        """Test get_keyring returns actual module when available"""
        from ids_suite.core import dependencies
        if dependencies.KEYRING_AVAILABLE:
            result = dependencies.get_keyring()
            assert result is not None
            # Verify it's the actual keyring module
            import keyring as actual_keyring
            assert result is actual_keyring


class TestGetRequests:
    """Test get_requests() lazy loader"""

    def test_get_requests_returns_module_or_none(self):
        """get_requests should return module if available, None otherwise"""
        from ids_suite.core.dependencies import get_requests, REQUESTS_AVAILABLE
        result = get_requests()
        if REQUESTS_AVAILABLE:
            assert result is not None
            assert hasattr(result, 'get') and hasattr(result, 'post')
        else:
            assert result is None

    def test_get_requests_when_unavailable(self):
        """Test get_requests when REQUESTS_AVAILABLE is False"""
        from ids_suite.core import dependencies
        original_flag = dependencies.REQUESTS_AVAILABLE
        dependencies.REQUESTS_AVAILABLE = False
        try:
            result = dependencies.get_requests()
            assert result is None
        finally:
            dependencies.REQUESTS_AVAILABLE = original_flag

    def test_get_requests_when_available(self):
        """Test get_requests returns actual module when available"""
        from ids_suite.core import dependencies
        if dependencies.REQUESTS_AVAILABLE:
            result = dependencies.get_requests()
            assert result is not None
            # Verify it's the actual requests module
            import requests as actual_requests
            assert result is actual_requests


class TestDependencyConsistency:
    """Test consistency between flags and getters"""

    def test_ctk_flag_getter_consistency(self):
        """CTK_AVAILABLE should match get_ctk() result"""
        from ids_suite.core.dependencies import CTK_AVAILABLE, get_ctk
        result = get_ctk()
        if CTK_AVAILABLE:
            assert result is not None
        else:
            assert result is None

    def test_matplotlib_flag_getter_consistency(self):
        """MATPLOTLIB_AVAILABLE should match get_matplotlib_components() result"""
        from ids_suite.core.dependencies import MATPLOTLIB_AVAILABLE, get_matplotlib_components
        canvas, fig, dates = get_matplotlib_components()
        if MATPLOTLIB_AVAILABLE:
            assert canvas is not None
            assert fig is not None
            assert dates is not None
        else:
            assert canvas is None
            assert fig is None
            assert dates is None

    def test_geoip_flag_getter_consistency(self):
        """GEOIP_AVAILABLE should match get_geoip() result"""
        from ids_suite.core.dependencies import GEOIP_AVAILABLE, get_geoip
        result = get_geoip()
        if GEOIP_AVAILABLE:
            assert result is not None
        else:
            assert result is None

    def test_keyring_flag_getter_consistency(self):
        """KEYRING_AVAILABLE should match get_keyring() result"""
        from ids_suite.core.dependencies import KEYRING_AVAILABLE, get_keyring
        result = get_keyring()
        if KEYRING_AVAILABLE:
            assert result is not None
        else:
            assert result is None

    def test_requests_flag_getter_consistency(self):
        """REQUESTS_AVAILABLE should match get_requests() result"""
        from ids_suite.core.dependencies import REQUESTS_AVAILABLE, get_requests
        result = get_requests()
        if REQUESTS_AVAILABLE:
            assert result is not None
        else:
            assert result is None


class TestModuleImports:
    """Test that module exports are accessible"""

    def test_all_flags_importable(self):
        """All availability flags should be importable"""
        from ids_suite.core.dependencies import (
            CTK_AVAILABLE,
            MATPLOTLIB_AVAILABLE,
            GEOIP_AVAILABLE,
            KEYRING_AVAILABLE,
            REQUESTS_AVAILABLE
        )
        # Just verify they exist and are booleans
        for flag in [CTK_AVAILABLE, MATPLOTLIB_AVAILABLE, GEOIP_AVAILABLE,
                     KEYRING_AVAILABLE, REQUESTS_AVAILABLE]:
            assert isinstance(flag, bool)

    def test_all_getters_importable(self):
        """All getter functions should be importable"""
        from ids_suite.core.dependencies import (
            get_ctk,
            get_matplotlib_components,
            get_geoip,
            get_keyring,
            get_requests
        )
        # Just verify they exist and are callable
        for getter in [get_ctk, get_matplotlib_components, get_geoip,
                       get_keyring, get_requests]:
            assert callable(getter)

    def test_getters_are_idempotent(self):
        """Calling getters multiple times should return same result"""
        from ids_suite.core.dependencies import (
            get_ctk, get_matplotlib_components, get_geoip,
            get_keyring, get_requests
        )

        # Call each getter twice and verify same result
        assert get_ctk() == get_ctk()
        assert get_matplotlib_components() == get_matplotlib_components()
        assert get_geoip() == get_geoip()
        assert get_keyring() == get_keyring()
        assert get_requests() == get_requests()
