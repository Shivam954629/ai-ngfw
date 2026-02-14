"""Network traffic acquisition module."""

from .csv_loader import CSVDataLoader

try:
    from .packet_capture import PacketCapture
except ImportError:
    PacketCapture = None  # Scapy not installed

__all__ = ["CSVDataLoader", "PacketCapture"]
