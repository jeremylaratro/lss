"""
Tests for ids_suite.ui.components.treeview_builder module
Tests treeview creation patterns for UI components
"""

import pytest
from unittest.mock import MagicMock, patch, call
import tkinter as tk
from tkinter import ttk


class TestTreeviewWrapperInit:
    """Test TreeviewWrapper initialization"""

    def test_init_stores_treeview(self):
        """TreeviewWrapper should store treeview reference"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)
        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        assert wrapper.treeview is mock_tree

    def test_init_stores_frame(self):
        """TreeviewWrapper should store frame reference"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)
        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        assert wrapper.frame is mock_frame

    def test_init_sets_default_sort_state(self):
        """TreeviewWrapper should initialize with no sort"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)
        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        assert wrapper.sort_column is None
        assert wrapper.sort_reverse is False


class TestTreeviewWrapperProxies:
    """Test TreeviewWrapper proxy methods"""

    @pytest.fixture
    def wrapper(self):
        """Create wrapper with mocked treeview"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)
        return TreeviewWrapper(mock_tree, mock_frame)

    def test_insert_proxies_to_treeview(self, wrapper):
        """insert() should proxy to treeview.insert()"""
        wrapper.insert('', 'end', values=('a', 'b'))
        wrapper.treeview.insert.assert_called_once_with('', 'end', values=('a', 'b'))

    def test_delete_proxies_to_treeview(self, wrapper):
        """delete() should proxy to treeview.delete()"""
        wrapper.delete('item1')
        wrapper.treeview.delete.assert_called_once_with('item1')

    def test_get_children_proxies_to_treeview(self, wrapper):
        """get_children() should proxy to treeview.get_children()"""
        wrapper.treeview.get_children.return_value = ['item1', 'item2']
        result = wrapper.get_children()
        assert result == ['item1', 'item2']

    def test_item_proxies_to_treeview(self, wrapper):
        """item() should proxy to treeview.item()"""
        wrapper.treeview.item.return_value = {'values': ['a', 'b']}
        result = wrapper.item('item1')
        assert result == {'values': ['a', 'b']}

    def test_selection_proxies_to_treeview(self, wrapper):
        """selection() should proxy to treeview.selection()"""
        wrapper.treeview.selection.return_value = ('item1',)
        result = wrapper.selection()
        assert result == ('item1',)

    def test_bind_proxies_to_treeview(self, wrapper):
        """bind() should proxy to treeview.bind()"""
        callback = lambda e: None
        wrapper.bind('<Double-1>', callback)
        wrapper.treeview.bind.assert_called_once_with('<Double-1>', callback)

    def test_tag_configure_proxies_to_treeview(self, wrapper):
        """tag_configure() should proxy to treeview.tag_configure()"""
        wrapper.tag_configure('high', foreground='red')
        wrapper.treeview.tag_configure.assert_called_once_with('high', foreground='red')


class TestTreeviewWrapperClear:
    """Test TreeviewWrapper.clear() method"""

    def test_clear_removes_all_items(self):
        """clear() should delete all children"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)

        # Mock get_children to return items
        mock_tree.get_children.return_value = ['item1', 'item2', 'item3']

        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        wrapper.clear()

        # Should call delete for each item
        assert mock_tree.delete.call_count == 3
        mock_tree.delete.assert_any_call('item1')
        mock_tree.delete.assert_any_call('item2')
        mock_tree.delete.assert_any_call('item3')

    def test_clear_handles_empty_tree(self):
        """clear() should handle empty treeview gracefully"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)
        mock_tree.get_children.return_value = []

        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        wrapper.clear()  # Should not raise
        assert mock_tree.delete.call_count == 0


class TestTreeviewWrapperSortState:
    """Test TreeviewWrapper sort state management"""

    def test_set_sort_state_updates_column(self):
        """set_sort_state() should update sort_column"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)

        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        wrapper.set_sort_state('timestamp', reverse=False)
        assert wrapper.sort_column == 'timestamp'

    def test_set_sort_state_updates_reverse(self):
        """set_sort_state() should update sort_reverse"""
        from ids_suite.ui.components.treeview_builder import TreeviewWrapper
        mock_tree = MagicMock(spec=ttk.Treeview)
        mock_frame = MagicMock(spec=ttk.Frame)

        wrapper = TreeviewWrapper(mock_tree, mock_frame)
        wrapper.set_sort_state('timestamp', reverse=True)
        assert wrapper.sort_reverse is True


class TestTreeviewBuilderInit:
    """Test TreeviewBuilder initialization"""

    def test_init_with_colors(self):
        """TreeviewBuilder should store colors dict"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        colors = {'red': '#ff0000', 'green': '#00ff00'}
        builder = TreeviewBuilder(colors)
        assert builder.colors == colors

    def test_init_without_colors(self):
        """TreeviewBuilder should default to empty colors"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        assert builder.colors == {}


class TestTreeviewBuilderCreate:
    """Test TreeviewBuilder.create() method"""

    @pytest.fixture
    def mock_tk(self):
        """Mock tkinter components"""
        with patch('ids_suite.ui.components.treeview_builder.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.components.treeview_builder.ttk.Treeview') as mock_tree, \
             patch('ids_suite.ui.components.treeview_builder.ttk.Scrollbar') as mock_scroll:
            mock_frame.return_value = MagicMock()
            mock_tree.return_value = MagicMock()
            mock_scroll.return_value = MagicMock()
            yield {
                'Frame': mock_frame,
                'Treeview': mock_tree,
                'Scrollbar': mock_scroll
            }

    def test_create_returns_wrapper(self, mock_tk):
        """create() should return TreeviewWrapper"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder, TreeviewWrapper
        builder = TreeviewBuilder()
        mock_parent = MagicMock()

        result = builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)]
        )

        assert isinstance(result, TreeviewWrapper)

    def test_create_builds_frame(self, mock_tk):
        """create() should create container frame"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()

        builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)]
        )

        mock_tk['Frame'].assert_called_once_with(mock_parent)

    def test_create_builds_treeview_with_columns(self, mock_tk):
        """create() should create treeview with column IDs"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()

        builder.create(
            parent=mock_parent,
            columns=[
                ('col1', 'Column 1', 100, 50, None),
                ('col2', 'Column 2', 150, 80, None),
            ]
        )

        # Check treeview was created with correct columns
        call_args = mock_tk['Treeview'].call_args
        assert call_args[1]['columns'] == ['col1', 'col2']
        assert call_args[1]['show'] == 'headings'  # Default (no tree)

    def test_create_with_show_tree(self, mock_tk):
        """create() with show_tree=True should show tree column"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()

        builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)],
            show_tree=True
        )

        call_args = mock_tk['Treeview'].call_args
        assert call_args[1]['show'] == 'tree headings'

    def test_create_configures_headings(self, mock_tk):
        """create() should configure column headings"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value

        builder.create(
            parent=mock_parent,
            columns=[
                ('col1', 'Column 1', 100, 50, None),
                ('col2', 'Column 2', 150, 80, None),
            ]
        )

        # Check heading was called for each column
        heading_calls = mock_tree_instance.heading.call_args_list
        assert len(heading_calls) == 2

    def test_create_with_sort_callback(self, mock_tk):
        """create() should attach sort callback to headings"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value
        sort_called = []

        def sort_callback(col):
            sort_called.append(col)

        builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)],
            sort_callback=sort_callback
        )

        # Heading should have command argument
        call_args = mock_tree_instance.heading.call_args
        assert 'command' in call_args[1]

    def test_create_configures_column_widths(self, mock_tk):
        """create() should configure column widths"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value

        builder.create(
            parent=mock_parent,
            columns=[
                ('col1', 'Column 1', 100, 50, 'w'),
                ('col2', 'Column 2', 150, 80, 'center'),
            ]
        )

        # Check column was called for each column
        column_calls = mock_tree_instance.column.call_args_list
        assert len(column_calls) == 2

        # Check specific configuration
        col1_call = [c for c in column_calls if c[0][0] == 'col1'][0]
        assert col1_call[1]['width'] == 100
        assert col1_call[1]['minwidth'] == 50
        assert col1_call[1]['anchor'] == 'w'

    def test_create_adds_scrollbars(self, mock_tk):
        """create() should add vertical and horizontal scrollbars"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()

        builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)]
        )

        # Should create 2 scrollbars (vertical and horizontal)
        assert mock_tk['Scrollbar'].call_count == 2

        # Check orient parameters
        scroll_calls = mock_tk['Scrollbar'].call_args_list
        orients = [c[1]['orient'] for c in scroll_calls]
        assert tk.VERTICAL in orients
        assert tk.HORIZONTAL in orients

    def test_create_configures_tags(self, mock_tk):
        """create() should configure tags for colors"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value

        builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)],
            tags={
                'high': '#ff0000',
                'low': '#00ff00',
            }
        )

        # Check tag_configure was called
        tag_calls = mock_tree_instance.tag_configure.call_args_list
        assert len(tag_calls) == 2

    def test_create_binds_events(self, mock_tk):
        """create() should bind specified events"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value

        double_click = lambda e: None
        right_click = lambda e: None

        builder.create(
            parent=mock_parent,
            columns=[('col1', 'Column 1', 100, 50, None)],
            events={
                '<Double-1>': double_click,
                '<Button-3>': right_click,
            }
        )

        # Check bind was called for each event
        bind_calls = mock_tree_instance.bind.call_args_list
        assert len(bind_calls) == 2


class TestTreeviewBuilderCreateSimple:
    """Test TreeviewBuilder.create_simple() method"""

    @pytest.fixture
    def mock_tk(self):
        """Mock tkinter components"""
        with patch('ids_suite.ui.components.treeview_builder.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.components.treeview_builder.ttk.Treeview') as mock_tree, \
             patch('ids_suite.ui.components.treeview_builder.ttk.Scrollbar') as mock_scroll:
            mock_frame.return_value = MagicMock()
            mock_tree.return_value = MagicMock()
            mock_scroll.return_value = MagicMock()
            yield {
                'Frame': mock_frame,
                'Treeview': mock_tree,
                'Scrollbar': mock_scroll
            }

    def test_create_simple_returns_wrapper(self, mock_tk):
        """create_simple() should return TreeviewWrapper"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder, TreeviewWrapper
        builder = TreeviewBuilder()
        mock_parent = MagicMock()

        result = builder.create_simple(
            parent=mock_parent,
            columns=['col1', 'col2'],
            headings=['Column 1', 'Column 2']
        )

        assert isinstance(result, TreeviewWrapper)

    def test_create_simple_uses_default_widths(self, mock_tk):
        """create_simple() should use 100 for default widths"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value

        builder.create_simple(
            parent=mock_parent,
            columns=['col1', 'col2'],
            headings=['Column 1', 'Column 2']
        )

        # Check column width defaults
        column_calls = mock_tree_instance.column.call_args_list
        for call in column_calls:
            assert call[1]['width'] == 100

    def test_create_simple_uses_provided_widths(self, mock_tk):
        """create_simple() should use provided widths"""
        from ids_suite.ui.components.treeview_builder import TreeviewBuilder
        builder = TreeviewBuilder()
        mock_parent = MagicMock()
        mock_tree_instance = mock_tk['Treeview'].return_value

        builder.create_simple(
            parent=mock_parent,
            columns=['col1', 'col2'],
            headings=['Column 1', 'Column 2'],
            widths=[150, 200]
        )

        # Check column widths
        column_calls = mock_tree_instance.column.call_args_list
        widths = [c[1]['width'] for c in column_calls]
        assert widths == [150, 200]


class TestFactoryFunctions:
    """Test factory functions for standard treeviews"""

    @pytest.fixture
    def mock_tk(self):
        """Mock tkinter components"""
        with patch('ids_suite.ui.components.treeview_builder.ttk.Frame') as mock_frame, \
             patch('ids_suite.ui.components.treeview_builder.ttk.Treeview') as mock_tree, \
             patch('ids_suite.ui.components.treeview_builder.ttk.Scrollbar') as mock_scroll:
            mock_frame.return_value = MagicMock()
            mock_tree.return_value = MagicMock()
            mock_scroll.return_value = MagicMock()
            yield {
                'Frame': mock_frame,
                'Treeview': mock_tree,
                'Scrollbar': mock_scroll
            }

    def test_create_standard_alerts_tree(self, mock_tk):
        """create_standard_alerts_tree() should create alerts treeview"""
        from ids_suite.ui.components.treeview_builder import (
            create_standard_alerts_tree, TreeviewWrapper
        )

        mock_parent = MagicMock()
        colors = {
            'red': '#ff0000',
            'orange': '#ffa500',
            'yellow': '#ffff00',
        }

        result = create_standard_alerts_tree(
            parent=mock_parent,
            colors=colors,
            sort_callback=lambda col: None,
            on_double_click=lambda e: None,
            on_right_click=lambda e: None
        )

        assert isinstance(result, TreeviewWrapper)
        # Check treeview was created with alert columns
        mock_tree_instance = mock_tk['Treeview'].return_value
        assert mock_tree_instance.heading.call_count >= 7  # 7 columns

    def test_create_standard_traffic_tree(self, mock_tk):
        """create_standard_traffic_tree() should create traffic treeview"""
        from ids_suite.ui.components.treeview_builder import (
            create_standard_traffic_tree, TreeviewWrapper
        )

        mock_parent = MagicMock()
        colors = {
            'green': '#00ff00',
            'cyan': '#00ffff',
            'yellow': '#ffff00',
            'purple': '#800080',
            'orange': '#ffa500',
        }

        result = create_standard_traffic_tree(
            parent=mock_parent,
            colors=colors,
            sort_callback=lambda col: None
        )

        assert isinstance(result, TreeviewWrapper)
        # Check treeview was created with traffic columns
        mock_tree_instance = mock_tk['Treeview'].return_value
        assert mock_tree_instance.heading.call_count >= 6  # 6 columns

    def test_create_standard_dns_tree(self, mock_tk):
        """create_standard_dns_tree() should create DNS treeview"""
        from ids_suite.ui.components.treeview_builder import (
            create_standard_dns_tree, TreeviewWrapper
        )

        mock_parent = MagicMock()
        colors = {
            'green': '#00ff00',
            'cyan': '#00ffff',
            'yellow': '#ffff00',
            'purple': '#800080',
            'orange': '#ffa500',
        }

        result = create_standard_dns_tree(
            parent=mock_parent,
            colors=colors,
            sort_callback=lambda col: None
        )

        assert isinstance(result, TreeviewWrapper)
        # Check treeview was created with DNS columns
        mock_tree_instance = mock_tk['Treeview'].return_value
        assert mock_tree_instance.heading.call_count >= 6  # 6 columns
