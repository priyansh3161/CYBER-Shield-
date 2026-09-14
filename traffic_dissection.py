"""
traffic_dissection.py
Stage 1: Traffic Dissection (PyShark / Scapy)

Reads a .pcap file and yields raw TCP packets grouped by 4-tuple flow.
Scapy is used as the primary engine (lightweight, no external tshark binary
needed). If pyshark + tshark are available on the host, pyshark can be
swapped in via USE_PYSHARK for deeper protocol decoding.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TrafficDissector:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def load_packets(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "scapy is not installed. Run: pip install scapy"
            )
        return rdpcap(self.pcap_path)

    def dissect(self) -> Dict[Tuple, List]:
        """
        Groups packets into TCP flows keyed by a normalized 4-tuple:
        (src_ip, src_port, dst_ip, dst_port) — normalized so both directions
        of the same conversation map to the same flow key.
        Returns: { flow_key: [packet, packet, ...] }
        """
        packets = self.load_packets()
        flows: Dict[Tuple, List] = defaultdict(list)

        for pkt in packets:
            if IP in pkt and TCP in pkt:
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                a = (ip_layer.src, tcp_layer.sport)
                b = (ip_layer.dst, tcp_layer.dport)
                # Normalize direction so A->B and B->A land in same flow
                flow_key = tuple(sorted([a, b]))
                flows[flow_key].append(pkt)

        return flows

    @staticmethod
    def flow_summary(flows: Dict[Tuple, List]) -> List[Dict]:
        summaries = []
        for flow_key, pkts in flows.items():
            (ip1, port1), (ip2, port2) = flow_key
            summaries.append({
                "endpoints": f"{ip1}:{port1} <-> {ip2}:{port2}",
                "packet_count": len(pkts),
            })
        return summaries
