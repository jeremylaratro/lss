"""
Optional dependency detection and management
"""

# CustomTkinter for modern UI
try:
    import customtkinter as ctk
    ctk.set_appearance_mode("dark")
    CTK_AVAILABLE = True
except ImportError:
    ctk = None
    CTK_AVAILABLE = False

# Matplotlib for charts and graphs
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    FigureCanvasTkAgg = None
    Figure = None
    mdates = None
    MATPLOTLIB_AVAILABLE = False

# GeoIP for geographic IP lookup
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    geoip2 = None
    GEOIP_AVAILABLE = False

# Keyring for secure API key storage
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    keyring = None
    KEYRING_AVAILABLE = False

# Requests for HTTP API calls
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False


def get_ctk():
    """Get CustomTkinter module if available"""
    if CTK_AVAILABLE:
        import customtkinter
        return customtkinter
    return None


def get_matplotlib_components():
    """Get matplotlib components if available"""
    if MATPLOTLIB_AVAILABLE:
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from matplotlib.figure import Figure
        import matplotlib.dates as mdates
        return FigureCanvasTkAgg, Figure, mdates
    return None, None, None


def get_geoip():
    """Get geoip2 module if available"""
    if GEOIP_AVAILABLE:
        import geoip2.database
        return geoip2
    return None


def get_keyring():
    """Get keyring module if available"""
    if KEYRING_AVAILABLE:
        import keyring
        return keyring
    return None


def get_requests():
    """Get requests module if available"""
    if REQUESTS_AVAILABLE:
        import requests
        return requests
    return None
