from __future__ import annotations

import base64
import os
import random
import socket

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import DeviceConfig, DnsTunnelExfilAttackConfig

_DNS_RECV_BUFFER = 512
_QUERY_FLAGS = b'\x01\x00'
_QDCOUNT = b'\x00\x01'
_ZERO_COUNTS = b'\x00\x00\x00\x00\x00\x00'
_QTYPE_A_QCLASS_IN = b'\x00\x01\x00\x01'


def encode_chunk_label(chunk: bytes) -> str:
    return base64.b32encode(chunk).decode('ascii').rstrip('=').lower()


def _encode_qname(domain: str) -> bytes:
    encoded = b''
    for label in domain.split('.'):
        label_bytes = label.encode('ascii')
        encoded += len(label_bytes).to_bytes(1, 'big') + label_bytes
    return encoded + b'\x00'


def build_dns_query(*, domain: str, query_id: int) -> bytes:
    header = query_id.to_bytes(2, 'big') + _QUERY_FLAGS + _QDCOUNT + _ZERO_COUNTS
    question = _encode_qname(domain) + _QTYPE_A_QCLASS_IN
    return header + question


class DnsTunnelExfilExecutor:
    """Encodes a staged payload as base32 subdomain labels sent via periodic DNS queries.

    Distinct traffic shape from exfil.py's single bulk POST burst - many
    small periodic queries instead of one big transfer, giving the
    multiclass detector two genuinely different exfil-class signatures.
    """

    def __init__(self, *, attack: DnsTunnelExfilAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        host = str(device.ip)
        remaining = self._attack.payload_size_bytes
        queries_sent = 0

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._attack.timeout_seconds)

            while remaining > 0:
                chunk_len = min(self._attack.chunk_size_bytes, remaining)
                chunk = os.urandom(chunk_len)
                label = encode_chunk_label(chunk)
                domain = f'{label}.{self._attack.base_domain}'
                query_id = random.randint(0, 0xFFFF)
                message = build_dns_query(domain=domain, query_id=query_id)

                sock.sendto(message, (host, self._attack.port))
                queries_sent += 1
                remaining -= chunk_len

                try:
                    sock.recvfrom(_DNS_RECV_BUFFER)
                except TimeoutError:
                    pass

        return f'queries_sent={queries_sent}'
