"""
stream_reconstructor.py
Stage 3: TCP Stream Reconstruction

Reassembles ordered, de-duplicated payload bytes per direction of each
TCP flow (client -> server, server -> client) using TCP sequence numbers,
so higher stages see a clean byte stream instead of individual packets.
"""

import uuid
from typing import Dict, List, Tuple

try:
    from scapy.all import TCP, IP, Raw
except ImportError:
    TCP = IP = Raw = None

from models import TCPStream
from protocol_identifier import ProtocolIdentifier


class StreamReconstructor:
    @staticmethod
    def reconstruct(flows: Dict[Tuple, List]) -> List[TCPStream]:
        streams = []

        for flow_key, pkts in flows.items():
            (ip1, port1), (ip2, port2) = flow_key

            # Determine "client" as the side that sent the first packet
            first_pkt = pkts[0]
            client_ip, client_port = first_pkt[IP].src, first_pkt[TCP].sport
            server_ip, server_port = first_pkt[IP].dst, first_pkt[TCP].dport

            client_segments = []  # (seq, payload)
            server_segments = []
            start_time = float(pkts[0].time)
            end_time = float(pkts[-1].time)

            for pkt in pkts:
                if Raw not in pkt:
                    continue
                payload = bytes(pkt[Raw].load)
                seq = pkt[TCP].seq
                if pkt[IP].src == client_ip and pkt[TCP].sport == client_port:
                    client_segments.append((seq, payload))
                else:
                    server_segments.append((seq, payload))

            client_bytes = StreamReconstructor._order_and_join(client_segments)
            server_bytes = StreamReconstructor._order_and_join(server_segments)

            proto = ProtocolIdentifier.identify(
                ports=[client_port, server_port],
                payload_sample=(server_bytes[:64] or client_bytes[:64]),
            )

            stream = TCPStream(
                stream_id=str(uuid.uuid4())[:8],
                src_ip=client_ip,
                dst_ip=server_ip,
                src_port=client_port,
                dst_port=server_port,
                protocol=proto,
                raw_client_bytes=client_bytes,
                raw_server_bytes=server_bytes,
                packet_count=len(pkts),
                start_time=start_time,
                end_time=end_time,
            )
            streams.append(stream)

        return streams

    @staticmethod
    def _order_and_join(segments: List[Tuple[int, bytes]]) -> bytes:
        """Sort by TCP sequence number and drop exact duplicate segments
        (basic retransmission handling) before joining."""
        if not segments:
            return b""
        segments = sorted(set(segments), key=lambda s: s[0])
        return b"".join(payload for _, payload in segments)
