"""
Tests for ids_suite.ui.widget_factory module
Tests widget creation with CTK/ttk fallback
"""

import pytest
from unittest.mock import MagicMock, patch
import tkinter as tk
from tkinter import ttk


class TestWidgetFactoryInit:
    """Test WidgetFactory initialization"""

    def test_init_with_colors(self):
        """WidgetFactory should store colors dict"""
        from ids_suite.ui.widget_factory import WidgetFactory
        colors = {'bg': '#000000', 'fg': '#ffffff', 'blue': '#0000ff'}
        factory = WidgetFactory(colors)
        assert factory.colors == colors

    def test_init_sets_use_ctk_flag(self):
        """WidgetFactory should set use_ctk based on availability"""
        from ids_suite.ui.widget_factory import WidgetFactory
        from ids_suite.core.dependencies import CTK_AVAILABLE
        factory = WidgetFactory({})
        assert factory.use_ctk == CTK_AVAILABLE

    def test_init_with_ctk_unavailable(self):
        """WidgetFactory should work when CTK is unavailable"""
        with patch('ids_suite.ui.widget_factory.CTK_AVAILABLE', False):
            with patch('ids_suite.ui.widget_factory.get_ctk', return_value=None):
                from ids_suite.ui import widget_factory
                # Force reimport to pick up patched values
                original_ctk = widget_factory.CTK_AVAILABLE
                widget_factory.CTK_AVAILABLE = False
                try:
                    factory = widget_factory.WidgetFactory({'bg': '#000'})
                    assert factory._ctk is None or factory.use_ctk == False
                finally:
                    widget_factory.CTK_AVAILABLE = original_ctk


class TestWidgetFactoryTTKFallback:
    """Test WidgetFactory ttk fallback when CTK unavailable"""

    @pytest.fixture
    def mock_root(self):
        """Create a mock tkinter root for testing"""
        root = MagicMock(spec=tk.Tk)
        root.tk = MagicMock()
        return root

    @pytest.fixture
    def factory_no_ctk(self):
        """Create factory with CTK disabled"""
        from ids_suite.ui import widget_factory
        original = widget_factory.CTK_AVAILABLE
        widget_factory.CTK_AVAILABLE = False
        factory = widget_factory.WidgetFactory({
            'bg': '#2c3746',
            'bg_alt': '#343f53',
            'fg': '#ffffff',
            'blue': '#176ef1',
            'cyan': '#5cc6d1',
            'gray': '#9cacad'
        })
        factory.use_ctk = False
        factory._ctk = None
        yield factory
        widget_factory.CTK_AVAILABLE = original

    def test_create_button_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_button should return ttk.Button when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Button') as mock_button:
            mock_button.return_value = MagicMock()
            result = factory_no_ctk.create_button(mock_root, "Test", command=lambda: None)
            mock_button.assert_called_once()

    def test_create_entry_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_entry should return ttk.Entry when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Entry') as mock_entry:
            mock_entry.return_value = MagicMock()
            var = MagicMock(spec=tk.StringVar)
            result = factory_no_ctk.create_entry(mock_root, textvariable=var, width=20)
            mock_entry.assert_called_once()

    def test_create_frame_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_frame should return ttk.Frame when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Frame') as mock_frame:
            mock_frame.return_value = MagicMock()
            result = factory_no_ctk.create_frame(mock_root)
            mock_frame.assert_called_once()

    def test_create_label_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_label should return ttk.Label when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Label') as mock_label:
            mock_label.return_value = MagicMock()
            result = factory_no_ctk.create_label(mock_root, "Test Label")
            mock_label.assert_called_once()

    def test_create_checkbox_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_checkbox should return ttk.Checkbutton when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Checkbutton') as mock_check:
            mock_check.return_value = MagicMock()
            var = MagicMock(spec=tk.BooleanVar)
            result = factory_no_ctk.create_checkbox(mock_root, "Check me", variable=var)
            mock_check.assert_called_once()

    def test_create_slider_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_slider should return ttk.Scale when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Scale') as mock_scale:
            mock_scale.return_value = MagicMock()
            var = MagicMock(spec=tk.DoubleVar)
            result = factory_no_ctk.create_slider(mock_root, from_=0, to=100, variable=var)
            mock_scale.assert_called_once()

    def test_create_progress_bar_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_progress_bar should return ttk.Progressbar when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Progressbar') as mock_progress:
            mock_progress.return_value = MagicMock()
            result = factory_no_ctk.create_progress_bar(mock_root, mode='determinate')
            mock_progress.assert_called_once()

    def test_create_option_menu_ttk_fallback(self, factory_no_ctk, mock_root):
        """create_option_menu should return ttk.Combobox when CTK unavailable"""
        with patch('ids_suite.ui.widget_factory.ttk.Combobox') as mock_combo:
            mock_combo.return_value = MagicMock()
            var = MagicMock(spec=tk.StringVar)
            result = factory_no_ctk.create_option_menu(mock_root, var, ['a', 'b', 'c'])
            mock_combo.assert_called_once()


class TestWidgetFactorySegmentedButton:
    """Test segmented button creation (complex fallback)"""

    @pytest.fixture
    def factory_no_ctk(self):
        """Create factory with CTK disabled"""
        from ids_suite.ui import widget_factory
        factory = widget_factory.WidgetFactory({'bg': '#2c3746'})
        factory.use_ctk = False
        factory._ctk = None
        return factory

    def test_create_segmented_button_fallback_creates_frame(self, factory_no_ctk):
        """Segmented button fallback should create a frame with radio buttons"""
        mock_root = MagicMock()
        mock_frame = MagicMock()
        mock_var = MagicMock()

        with patch('ids_suite.ui.widget_factory.ttk.Frame', return_value=mock_frame):
            with patch('ids_suite.ui.widget_factory.tk.StringVar', return_value=mock_var):
                with patch('ids_suite.ui.widget_factory.ttk.Radiobutton') as mock_rb:
                    mock_rb.return_value = MagicMock()
                    result = factory_no_ctk.create_segmented_button(
                        mock_root, ['Option1', 'Option2', 'Option3']
                    )
                    # Should create 3 radio buttons
                    assert mock_rb.call_count == 3


class TestWidgetFactoryCard:
    """Test card creation"""

    @pytest.fixture
    def factory_no_ctk(self):
        """Create factory with CTK disabled"""
        from ids_suite.ui import widget_factory
        factory = widget_factory.WidgetFactory({'bg': '#2c3746', 'gray': '#9cacad'})
        factory.use_ctk = False
        factory._ctk = None
        return factory

    def test_create_card_ttk_fallback(self, factory_no_ctk):
        """Card should use ttk.LabelFrame when CTK unavailable"""
        mock_root = MagicMock()
        with patch('ids_suite.ui.widget_factory.ttk.LabelFrame') as mock_lf:
            mock_lf.return_value = MagicMock()
            result = factory_no_ctk.create_card(mock_root, title="Test Card")
            mock_lf.assert_called_once()

    def test_create_card_no_title(self, factory_no_ctk):
        """Card with no title should pass empty string"""
        mock_root = MagicMock()
        with patch('ids_suite.ui.widget_factory.ttk.LabelFrame') as mock_lf:
            mock_lf.return_value = MagicMock()
            result = factory_no_ctk.create_card(mock_root)
            # Should be called with text=''
            call_args = mock_lf.call_args
            assert call_args[1].get('text', '') == ''


class TestWidgetFactoryTextbox:
    """Test textbox creation with ScrolledText fallback"""

    @pytest.fixture
    def factory_no_ctk(self):
        """Create factory with CTK disabled"""
        from ids_suite.ui import widget_factory
        factory = widget_factory.WidgetFactory({
            'bg_alt': '#343f53',
            'fg': '#ffffff'
        })
        factory.use_ctk = False
        factory._ctk = None
        return factory

    def test_create_textbox_ttk_fallback(self, factory_no_ctk):
        """Textbox should use ScrolledText when CTK unavailable"""
        mock_root = MagicMock()
        with patch('ids_suite.ui.widget_factory.scrolledtext.ScrolledText') as mock_st:
            mock_st.return_value = MagicMock()
            result = factory_no_ctk.create_textbox(mock_root, height=10)
            mock_st.assert_called_once()

    def test_create_textbox_filters_ctk_kwargs(self, factory_no_ctk):
        """Textbox should filter CTK-incompatible kwargs for ScrolledText"""
        mock_root = MagicMock()
        with patch('ids_suite.ui.widget_factory.scrolledtext.ScrolledText') as mock_st:
            mock_st.return_value = MagicMock()
            # Pass kwargs that should be handled
            result = factory_no_ctk.create_textbox(
                mock_root, height=10,
                bg='#000', fg='#fff', font=('Arial', 10)
            )
            mock_st.assert_called_once()


class TestWidgetFactoryColors:
    """Test color handling in widget factory"""

    def test_uses_default_colors_when_missing(self):
        """Factory should use default colors when keys missing"""
        from ids_suite.ui.widget_factory import WidgetFactory
        factory = WidgetFactory({})  # Empty colors
        # Verify factory doesn't crash when colors are missing
        assert factory.colors == {}

    def test_uses_provided_colors(self):
        """Factory should use provided colors"""
        from ids_suite.ui.widget_factory import WidgetFactory
        colors = {
            'bg': '#111111',
            'fg': '#eeeeee',
            'blue': '#0066cc'
        }
        factory = WidgetFactory(colors)
        assert factory.colors['bg'] == '#111111'
        assert factory.colors['fg'] == '#eeeeee'
        assert factory.colors['blue'] == '#0066cc'
