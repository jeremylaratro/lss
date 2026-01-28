"""
Tests for ids_suite.ui.tabs.base_tab module
Tests base tab class patterns for UI tabs
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import threading
import time
import tkinter as tk
from tkinter import ttk


class TestBaseTabInit:
    """Test BaseTab initialization"""

    @pytest.fixture
    def mock_app(self):
        """Create mock SecurityControlPanel"""
        app = MagicMock()
        app.root = MagicMock()
        app.root.after = lambda delay, fn: fn()
        app.colors = {'bg': '#000000', 'fg': '#ffffff'}
        app.widgets = MagicMock()
        app.style = MagicMock()
        return app

    @pytest.fixture
    def mock_parent(self):
        """Create mock parent widget"""
        return MagicMock(spec=tk.Widget)

    def test_init_stores_parent(self, mock_parent, mock_app):
        """BaseTab should store parent reference"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        # Create a concrete implementation
        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                pass

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            tab = TestTab(mock_parent, mock_app)
            assert tab.parent is mock_parent

    def test_init_stores_app(self, mock_parent, mock_app):
        """BaseTab should store app reference"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                pass

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            tab = TestTab(mock_parent, mock_app)
            assert tab.app is mock_app

    def test_init_creates_frame(self, mock_parent, mock_app):
        """BaseTab should create ttk.Frame"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                pass

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame') as mock_frame:
            mock_frame.return_value = MagicMock()
            tab = TestTab(mock_parent, mock_app)
            mock_frame.assert_called_once()

    def test_init_calls_create_widgets(self, mock_parent, mock_app):
        """BaseTab should call _create_widgets on init"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        widgets_created = []

        class TestTab(BaseTab):
            def _create_widgets(self):
                widgets_created.append(True)
            def refresh(self):
                pass

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            tab = TestTab(mock_parent, mock_app)
            assert widgets_created == [True]


class TestBaseTabAbstractMethods:
    """Test BaseTab abstract method enforcement"""

    def test_cannot_instantiate_without_create_widgets(self):
        """BaseTab subclass must implement _create_widgets"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class IncompleteTab(BaseTab):
            def refresh(self):
                pass

        mock_parent = MagicMock()
        mock_app = MagicMock()

        with pytest.raises(TypeError) as exc_info:
            with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
                tab = IncompleteTab(mock_parent, mock_app)
        assert "_create_widgets" in str(exc_info.value)

    def test_cannot_instantiate_without_refresh(self):
        """BaseTab subclass must implement refresh"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class IncompleteTab(BaseTab):
            def _create_widgets(self):
                pass

        mock_parent = MagicMock()
        mock_app = MagicMock()

        with pytest.raises(TypeError) as exc_info:
            with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
                tab = IncompleteTab(mock_parent, mock_app)
        assert "refresh" in str(exc_info.value)


class TestBaseTabRunAsync:
    """Test BaseTab.run_async() method"""

    @pytest.fixture
    def tab(self):
        """Create a test tab instance"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                pass

        mock_parent = MagicMock()
        mock_app = MagicMock()
        mock_app.root = MagicMock()
        mock_app.root.after = lambda delay, fn: fn()
        mock_app.show_progress = MagicMock()
        mock_app.hide_progress = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            return TestTab(mock_parent, mock_app)

    def test_run_async_executes_work_function(self, tab):
        """run_async() should execute work function"""
        work_called = []
        def work():
            work_called.append(True)
            return "result"

        tab.run_async(work_fn=work)
        time.sleep(0.1)  # Allow thread to complete
        assert work_called == [True]

    def test_run_async_calls_on_complete_with_result(self, tab):
        """run_async() should call on_complete with work result"""
        results = []
        def work():
            return "test_result"
        def on_complete(result):
            results.append(result)

        tab.run_async(work_fn=work, on_complete=on_complete)
        time.sleep(0.1)
        assert results == ["test_result"]

    def test_run_async_calls_on_error_on_exception(self, tab):
        """run_async() should call on_error when work raises exception"""
        errors = []
        def work():
            raise ValueError("test error")
        def on_error(e):
            errors.append(str(e))

        tab.run_async(work_fn=work, on_error=on_error)
        time.sleep(0.1)
        assert "test error" in errors[0]

    def test_run_async_shows_progress_when_message_provided(self, tab):
        """run_async() should show progress when progress_message set"""
        def work():
            return "result"

        tab.run_async(work_fn=work, progress_message="Loading...")
        time.sleep(0.05)
        tab.app.show_progress.assert_called_with("Loading...")

    def test_run_async_hides_progress_on_complete(self, tab):
        """run_async() should hide progress after completion"""
        def work():
            return "result"

        tab.run_async(work_fn=work, progress_message="Loading...")
        time.sleep(0.1)
        tab.app.hide_progress.assert_called()

    def test_run_async_hides_progress_on_error(self, tab):
        """run_async() should hide progress even on error"""
        def work():
            raise ValueError("error")
        def on_error(e):
            pass

        tab.run_async(work_fn=work, on_error=on_error, progress_message="Loading...")
        time.sleep(0.1)
        tab.app.hide_progress.assert_called()

    def test_run_async_default_error_handling(self, tab):
        """run_async() should print error if no on_error handler"""
        def work():
            raise ValueError("unhandled error")

        # Should not raise, just print
        with patch('builtins.print') as mock_print:
            tab.run_async(work_fn=work)
            time.sleep(0.1)
            # Verify print was called with error message
            assert mock_print.called


class TestBaseTabHelperMethods:
    """Test BaseTab helper methods"""

    @pytest.fixture
    def tab(self):
        """Create a test tab instance"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                pass

        mock_parent = MagicMock()
        mock_app = MagicMock()
        mock_app.widgets = MagicMock()
        mock_app.colors = {'bg': '#000000', 'fg': '#ffffff', 'blue': '#0000ff'}
        mock_app.style = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            return TestTab(mock_parent, mock_app)

    def test_get_widget_factory_returns_app_widgets(self, tab):
        """get_widget_factory() should return app.widgets"""
        factory = tab.get_widget_factory()
        assert factory is tab.app.widgets

    def test_get_widget_factory_returns_none_if_no_widgets(self, tab):
        """get_widget_factory() should return None if app has no widgets"""
        del tab.app.widgets
        factory = tab.get_widget_factory()
        assert factory is None

    def test_get_colors_returns_app_colors(self, tab):
        """get_colors() should return app.colors"""
        colors = tab.get_colors()
        assert colors == {'bg': '#000000', 'fg': '#ffffff', 'blue': '#0000ff'}

    def test_get_colors_returns_empty_dict_if_no_colors(self, tab):
        """get_colors() should return empty dict if app has no colors"""
        del tab.app.colors
        colors = tab.get_colors()
        assert colors == {}

    def test_get_style_returns_app_style(self, tab):
        """get_style() should return app.style"""
        style = tab.get_style()
        assert style is tab.app.style

    def test_get_style_creates_new_style_if_missing(self, tab):
        """get_style() should create new Style if app has no style"""
        del tab.app.style
        with patch('ids_suite.ui.tabs.base_tab.ttk.Style') as mock_style:
            mock_style.return_value = MagicMock()
            style = tab.get_style()
            mock_style.assert_called_once()


class TestBaseTabCreateHeader:
    """Test BaseTab.create_header() method"""

    @pytest.fixture
    def tab(self):
        """Create a test tab instance"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                pass

        mock_parent = MagicMock()
        mock_app = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            return TestTab(mock_parent, mock_app)

    def test_create_header_returns_tuple(self, tab):
        """create_header() should return (frame, label) tuple"""
        mock_parent = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.tabs.base_tab.ttk.Label') as mock_label:
            mock_frame.return_value = MagicMock()
            mock_label.return_value = MagicMock()

            result = tab.create_header(mock_parent, "Test Title")

            assert isinstance(result, tuple)
            assert len(result) == 2

    def test_create_header_creates_frame(self, tab):
        """create_header() should create header frame"""
        mock_parent = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.tabs.base_tab.ttk.Label') as mock_label:
            mock_frame.return_value = MagicMock()
            mock_label.return_value = MagicMock()

            tab.create_header(mock_parent, "Test Title")

            mock_frame.assert_called_once_with(mock_parent)

    def test_create_header_creates_label_with_icon(self, tab):
        """create_header() should create label with icon and title"""
        mock_parent = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.tabs.base_tab.ttk.Label') as mock_label:
            mock_frame.return_value = MagicMock()
            mock_label.return_value = MagicMock()

            tab.create_header(mock_parent, "Test Title", icon="󰒓")

            # Check label was created with correct text
            call_args = mock_label.call_args
            assert "󰒓 Test Title" in call_args[1]['text']

    def test_create_header_uses_title_style(self, tab):
        """create_header() should use Title.TLabel style"""
        mock_parent = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.tabs.base_tab.ttk.Label') as mock_label:
            mock_frame.return_value = MagicMock()
            mock_label.return_value = MagicMock()

            tab.create_header(mock_parent, "Test Title")

            call_args = mock_label.call_args
            assert call_args[1]['style'] == 'Title.TLabel'


class TestBaseTabCreateRefreshButton:
    """Test BaseTab.create_refresh_button() method"""

    @pytest.fixture
    def tab(self):
        """Create a test tab instance"""
        from ids_suite.ui.tabs.base_tab import BaseTab

        class TestTab(BaseTab):
            def _create_widgets(self):
                pass
            def refresh(self):
                self.refresh_called = True

        mock_parent = MagicMock()
        mock_app = MagicMock()
        mock_app.widgets = None  # No widget factory

        with patch('ids_suite.ui.tabs.base_tab.ttk.Frame'):
            t = TestTab(mock_parent, mock_app)
            t.refresh_called = False
            return t

    def test_create_refresh_button_returns_widget(self, tab):
        """create_refresh_button() should return a button widget"""
        mock_parent = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Button') as mock_button:
            mock_button.return_value = MagicMock()
            result = tab.create_refresh_button(mock_parent)
            assert result is not None

    def test_create_refresh_button_uses_default_command(self, tab):
        """create_refresh_button() should use self.refresh as default"""
        mock_parent = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Button') as mock_button:
            mock_button.return_value = MagicMock()
            tab.create_refresh_button(mock_parent)

            call_args = mock_button.call_args
            # Default command should be tab.refresh
            assert call_args[1]['command'] == tab.refresh

    def test_create_refresh_button_uses_custom_command(self, tab):
        """create_refresh_button() should use provided command"""
        mock_parent = MagicMock()
        custom_cmd = lambda: None

        with patch('ids_suite.ui.tabs.base_tab.ttk.Button') as mock_button:
            mock_button.return_value = MagicMock()
            tab.create_refresh_button(mock_parent, command=custom_cmd)

            call_args = mock_button.call_args
            assert call_args[1]['command'] == custom_cmd

    def test_create_refresh_button_uses_widget_factory_if_available(self, tab):
        """create_refresh_button() should use widget factory if available"""
        mock_parent = MagicMock()
        mock_factory = MagicMock()
        mock_factory.create_button.return_value = MagicMock()
        tab.app.widgets = mock_factory

        result = tab.create_refresh_button(mock_parent)

        mock_factory.create_button.assert_called_once()

    def test_create_refresh_button_packs_to_right(self, tab):
        """create_refresh_button() should pack button to right"""
        mock_parent = MagicMock()
        mock_btn = MagicMock()

        with patch('ids_suite.ui.tabs.base_tab.ttk.Button', return_value=mock_btn):
            tab.create_refresh_button(mock_parent)
            mock_btn.pack.assert_called_once_with(side=tk.RIGHT, padx=5)
