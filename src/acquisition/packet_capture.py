"""Real-time packet capture for flow-level traffic collection."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from threading import Thread
from typing import Callable, Optional
import time

try:
    from scapy.all import sniff, Ether, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class NetworkFlow:
    """Represents a network flow for threat analysis."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_volume: int
    duration: float
    start_time: float
    last_seen: float


class PacketCapture:
    """Capture network packets and aggregate into flows."""

    def __init__(self, interface: Optional[str] = None, flow_timeout: float = 60.0):
        self.interface = interface
        self.flow_timeout = flow_timeout
        self.flows: dict[tuple, NetworkFlow] = {}
        self._running = False
        self._thread: Optional[Thread] = None
        self._callback: Optional[Callable[[NetworkFlow], None]] = None

    def _get_flow_key(self, pkt) -> Optional[tuple]:
        """Extract 5-tuple flow key from packet."""
        if not pkt.haslayer(IP):
            return None
        ip_layer = pkt[IP]
        proto = ip_layer.proto
        if pkt.haslayer(TCP):
            return (
                ip_layer.src, ip_layer.dst,
                pkt[TCP].sport, pkt[TCP].dport, "TCP"
            )
        if pkt.haslayer(UDP):
            return (
                ip_layer.src, ip_layer.dst,
                pkt[UDP].sport, pkt[UDP].dport, "UDP"
            )
        return (ip_layer.src, ip_layer.dst, 0, 0, "ICMP" if proto == 1 else "Other")

    def _process_packet(self, pkt):
        """Process captured packet and update flow stats."""
        if not SCAPY_AVAILABLE or not pkt.haslayer(IP):
            return

        key = self._get_flow_key(pkt)
        if not key:
            return

        now = time.time()
        ip = pkt[IP]
        length = len(pkt)

        if key in self.flows:
            flow = self.flows[key]
            flow.packet_count += 1
            flow.byte_volume += length
            flow.last_seen = now
            flow.duration = now - flow.start_time
        else:
            self.flows[key] = NetworkFlow(
                src_ip=key[0],
                dst_ip=key[1],
                src_port=key[2],
                dst_port=key[3],
                protocol=key[4],
                packet_count=1,
                byte_volume=length,
                duration=0.0,
                start_time=now,
                last_seen=now,
            )

        # Check for expired flows and trigger callback
        self._flush_expired_flows(now)

    def _flush_expired_flows(self, now: float):
        """Emit and remove flows that have exceeded timeout."""
        expired = [
            k for k, v in self.flows.items()
            if now - v.last_seen > self.flow_timeout
        ]
        for k in expired:
            flow = self.flows.pop(k)
            if self._callback and flow.packet_count >= 2:
                self._callback(flow)

    def start(self, callback: Optional[Callable[[NetworkFlow], None]] = None):
        """Start packet capture in background thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")

        self._callback = callback
        self._running = True

        def _sniff():
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )

        self._thread = Thread(target=_sniff, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop packet capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def get_flow_dict(self, flow: NetworkFlow) -> dict:
        """Convert NetworkFlow to dict for API/model input."""
        return {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "packet_count": flow.packet_count,
            "byte_volume": flow.byte_volume,
            "duration": flow.duration,
            "timestamp": datetime.utcnow().isoformat(),
        }
