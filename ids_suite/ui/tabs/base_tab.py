"""
Base Tab Class for Security Suite Control Panel
Provides common functionality for all tab implementations
"""

from abc import ABC, abstractmethod
import tkinter as tk
from tkinter import ttk
import threading
from typing import Callable, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ids_suite.ui.main_window import SecurityControlPanel


class BaseTab(ABC):
    """
    Abstract base class for all tab implementations.

    Provides common patterns extracted from main_window.py:
    - Consistent tab initialization
    - Threading pattern for async operations
    - Common widget creation patterns
    - Refresh mechanism

    Each tab should:
    1. Inherit from this class
    2. Implement _create_widgets() to build the UI
    3. Implement refresh() to update data
    4. Use run_async() for background operations
    """

    def __init__(self, parent: tk.Widget, app: 'SecurityControlPanel'):
        """
        Initialize base tab.

        Args:
            parent: Parent widget (typically the notebook)
            app: Reference to main SecurityControlPanel instance
        """
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent, padding="10")

        # Create the tab-specific UI
        self._create_widgets()

    @abstractmethod
    def _create_widgets(self) -> None:
        """
        Create tab-specific widgets.

        This method must be implemented by subclasses to build the tab UI.
        Use self.frame as the container for all widgets.
        """
        pass

    @abstractmethod
    def refresh(self) -> None:
        """
        Refresh tab data.

        This method must be implemented by subclasses to update the tab's data.
        Called when user manually refreshes or during auto-refresh cycles.
        """
        pass

    def run_async(
        self,
        work_fn: Callable[[], Any],
        on_complete: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        progress_message: Optional[str] = None
    ) -> None:
        """
        Run work in background thread, update UI on completion.

        This method implements the common threading pattern found throughout
        main_window.py where work is done in a daemon thread and results are
        posted back to the main UI thread using root.after(0, ...).

        Args:
            work_fn: Function to execute in background thread (no args)
            on_complete: Callback with result when work succeeds
            on_error: Callback with exception if work fails
            progress_message: Optional message to show in progress bar

        Example:
            def do_work():
                # Long running operation
                return some_data

            def on_done(data):
                # Update UI with data
                self.tree.insert('', 'end', values=data)

            self.run_async(do_work, on_complete=on_done,
                          progress_message="Loading data...")
        """
        def thread_worker():
            try:
                # Execute work in background thread
                result = work_fn()

                # Schedule UI update on main thread
                def update_ui():
                    if progress_message and hasattr(self.app, 'hide_progress'):
                        self.app.hide_progress()

                    if on_complete:
                        on_complete(result)

                self.app.root.after(0, update_ui)

            except Exception as e:
                # Handle errors on main thread
                def handle_error():
                    if progress_message and hasattr(self.app, 'hide_progress'):
                        self.app.hide_progress()

                    if on_error:
                        on_error(e)
                    else:
                        # Default error handling
                        print(f"Error in async operation: {e}")

                self.app.root.after(0, handle_error)

        # Show progress indicator if message provided
        if progress_message and hasattr(self.app, 'show_progress'):
            self.app.show_progress(progress_message)

        # Start daemon thread
        threading.Thread(target=thread_worker, daemon=True).start()

    def get_widget_factory(self):
        """Get the widget factory from the app for consistent UI creation."""
        return self.app.widgets if hasattr(self.app, 'widgets') else None

    def get_colors(self) -> dict:
        """Get the color scheme from the app."""
        return self.app.colors if hasattr(self.app, 'colors') else {}

    def get_style(self) -> ttk.Style:
        """Get the ttk.Style instance from the app."""
        return self.app.style if hasattr(self.app, 'style') else ttk.Style()

    def create_header(
        self,
        parent: tk.Widget,
        title: str,
        icon: str = "󰒓"
    ) -> tuple[ttk.Frame, ttk.Label]:
        """
        Create a standard tab header with title.

        Args:
            parent: Parent widget
            title: Title text (without icon)
            icon: Icon character (Nerd Font)

        Returns:
            Tuple of (header_frame, title_label) for further customization
        """
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(
            header_frame,
            text=f"{icon} {title}",
            style='Title.TLabel'
        )
        title_label.pack(side=tk.LEFT)

        return header_frame, title_label

    def create_refresh_button(
        self,
        parent: tk.Widget,
        command: Optional[Callable] = None
    ) -> tk.Widget:
        """
        Create a standard refresh button.

        Args:
            parent: Parent widget
            command: Command to execute (defaults to self.refresh)

        Returns:
            The created button widget
        """
        factory = self.get_widget_factory()
        cmd = command if command else self.refresh

        if factory:
            btn = factory.create_button(parent, text="󰑐 Refresh", command=cmd)
        else:
            btn = ttk.Button(parent, text="󰑐 Refresh", command=cmd)

        btn.pack(side=tk.RIGHT, padx=5)
        return btn
