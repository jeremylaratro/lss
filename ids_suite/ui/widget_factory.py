"""
Widget Factory for CustomTkinter/ttk abstraction
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Dict, Any, Optional, List, Callable

from ids_suite.core.dependencies import CTK_AVAILABLE, get_ctk


class WidgetFactory:
    """Factory for creating widgets with CustomTkinter or ttk fallback.

    This factory enables a modern UI appearance when CustomTkinter is available,
    while gracefully falling back to ttk widgets otherwise.
    """

    def __init__(self, colors: Dict[str, str]):
        self.colors = colors
        self.use_ctk = CTK_AVAILABLE
        self._ctk = get_ctk() if CTK_AVAILABLE else None

    def create_button(
        self,
        parent: tk.Widget,
        text: str,
        command: Optional[Callable] = None,
        **kwargs
    ) -> tk.Widget:
        """Create a styled button"""
        if self.use_ctk:
            return self._ctk.CTkButton(
                parent, text=text, command=command,
                fg_color=self.colors.get('blue', '#176ef1'),
                hover_color=self.colors.get('cyan', '#5cc6d1'),
                text_color=self.colors.get('fg', '#ffffff'),
                corner_radius=8, height=32, **kwargs
            )
        return ttk.Button(parent, text=text, command=command)

    def create_entry(
        self,
        parent: tk.Widget,
        textvariable: Optional[tk.StringVar] = None,
        width: int = 20,
        **kwargs
    ) -> tk.Widget:
        """Create a styled entry field"""
        if self.use_ctk:
            return self._ctk.CTkEntry(
                parent, textvariable=textvariable, width=width * 8,
                fg_color=self.colors.get('bg_alt', '#343f53'),
                text_color=self.colors.get('fg', '#ffffff'),
                border_color=self.colors.get('gray', '#9cacad'),
                corner_radius=6, **kwargs
            )
        return ttk.Entry(parent, textvariable=textvariable, width=width)

    def create_frame(
        self,
        parent: tk.Widget,
        corner_radius: int = 0,
        **kwargs
    ) -> tk.Widget:
        """Create a styled frame"""
        if self.use_ctk and corner_radius > 0:
            return self._ctk.CTkFrame(
                parent, fg_color=self.colors.get('bg_alt', '#343f53'),
                corner_radius=corner_radius, **kwargs
            )
        return ttk.Frame(parent, **kwargs)

    def create_label(
        self,
        parent: tk.Widget,
        text: str,
        **kwargs
    ) -> tk.Widget:
        """Create a styled label"""
        if self.use_ctk:
            return self._ctk.CTkLabel(
                parent, text=text,
                text_color=self.colors.get('fg', '#ffffff'),
                **kwargs
            )
        return ttk.Label(parent, text=text, **kwargs)

    def create_textbox(
        self,
        parent: tk.Widget,
        height: int = 10,
        **kwargs
    ) -> tk.Widget:
        """Create a styled text box with scrollbar"""
        # Filter out ScrolledText-specific kwargs that CTkTextbox doesn't accept
        ctk_incompatible = {'bg', 'fg', 'font', 'insertbackground', 'wrap', 'relief', 'borderwidth'}
        ctk_kwargs = {k: v for k, v in kwargs.items() if k not in ctk_incompatible}

        if self.use_ctk:
            return self._ctk.CTkTextbox(
                parent, height=height * 20,
                fg_color=self.colors.get('bg_alt', '#343f53'),
                text_color=self.colors.get('fg', '#ffffff'),
                corner_radius=6, **ctk_kwargs
            )
        # For ScrolledText fallback, extract styling kwargs and pass rest
        bg = kwargs.pop('bg', self.colors.get('bg_alt', '#343f53'))
        fg = kwargs.pop('fg', self.colors.get('fg', '#ffffff'))
        font = kwargs.pop('font', ('Hack Nerd Font', 9))
        kwargs.pop('insertbackground', None)  # Remove if present
        return scrolledtext.ScrolledText(parent, height=height, bg=bg, fg=fg, font=font, **kwargs)

    def create_checkbox(
        self,
        parent: tk.Widget,
        text: str,
        variable: Optional[tk.BooleanVar] = None,
        **kwargs
    ) -> tk.Widget:
        """Create a styled checkbox"""
        if self.use_ctk:
            return self._ctk.CTkCheckBox(
                parent, text=text, variable=variable,
                fg_color=self.colors.get('blue', '#176ef1'),
                hover_color=self.colors.get('cyan', '#5cc6d1'),
                text_color=self.colors.get('fg', '#ffffff'),
                **kwargs
            )
        return ttk.Checkbutton(parent, text=text, variable=variable)

    def create_segmented_button(
        self,
        parent: tk.Widget,
        values: List[str],
        command: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> tk.Widget:
        """Create a segmented button (radio button group)"""
        if self.use_ctk:
            return self._ctk.CTkSegmentedButton(
                parent, values=values, command=command,
                fg_color=self.colors.get('bg_alt', '#343f53'),
                selected_color=self.colors.get('blue', '#176ef1'),
                selected_hover_color=self.colors.get('cyan', '#5cc6d1'),
                unselected_color=self.colors.get('bg', '#2c3746'),
                text_color=self.colors.get('fg', '#ffffff'),
                **kwargs
            )
        # Fallback to radio buttons in a frame
        frame = ttk.Frame(parent)
        var = tk.StringVar(value=values[0] if values else '')
        for val in values:
            rb = ttk.Radiobutton(
                frame, text=val, variable=var, value=val,
                command=lambda v=val: command(v) if command else None
            )
            rb.pack(side=tk.LEFT, padx=2)
        frame._variable = var
        return frame

    def create_card(
        self,
        parent: tk.Widget,
        title: Optional[str] = None,
        **kwargs
    ) -> tk.Widget:
        """Create a styled card (container with border and optional title)"""
        if self.use_ctk:
            card = self._ctk.CTkFrame(
                parent, fg_color=self.colors.get('bg_alt', '#343f53'),
                corner_radius=10, border_width=1,
                border_color=self.colors.get('gray', '#9cacad'),
                **kwargs
            )
            if title:
                self._ctk.CTkLabel(
                    card, text=title,
                    font=('Hack Nerd Font', 12, 'bold'),
                    text_color=self.colors.get('cyan', '#5cc6d1')
                ).pack(anchor=tk.W, padx=10, pady=(10, 5))
            return card
        return ttk.LabelFrame(parent, text=title if title else '', padding="10")

    def create_slider(
        self,
        parent: tk.Widget,
        from_: float = 0,
        to: float = 100,
        variable: Optional[tk.DoubleVar] = None,
        **kwargs
    ) -> tk.Widget:
        """Create a styled slider"""
        if self.use_ctk:
            return self._ctk.CTkSlider(
                parent, from_=from_, to=to, variable=variable,
                fg_color=self.colors.get('bg_alt', '#343f53'),
                progress_color=self.colors.get('blue', '#176ef1'),
                button_color=self.colors.get('cyan', '#5cc6d1'),
                **kwargs
            )
        return ttk.Scale(parent, from_=from_, to=to, variable=variable, **kwargs)

    def create_progress_bar(
        self,
        parent: tk.Widget,
        mode: str = 'determinate',
        **kwargs
    ) -> tk.Widget:
        """Create a styled progress bar"""
        if self.use_ctk:
            return self._ctk.CTkProgressBar(
                parent, mode=mode,
                fg_color=self.colors.get('bg_alt', '#343f53'),
                progress_color=self.colors.get('blue', '#176ef1'),
                **kwargs
            )
        return ttk.Progressbar(parent, mode=mode, **kwargs)

    def create_option_menu(
        self,
        parent: tk.Widget,
        variable: tk.StringVar,
        values: List[str],
        command: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> tk.Widget:
        """Create a styled dropdown menu"""
        if self.use_ctk:
            return self._ctk.CTkOptionMenu(
                parent, variable=variable, values=values, command=command,
                fg_color=self.colors.get('bg_alt', '#343f53'),
                button_color=self.colors.get('blue', '#176ef1'),
                button_hover_color=self.colors.get('cyan', '#5cc6d1'),
                text_color=self.colors.get('fg', '#ffffff'),
                **kwargs
            )
        return ttk.Combobox(parent, textvariable=variable, values=values, state='readonly')
