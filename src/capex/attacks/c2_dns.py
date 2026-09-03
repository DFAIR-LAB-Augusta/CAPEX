from __future__ import annotations

import random
import socket
import time

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import C2DnsBeaconAttackConfig, DeviceConfig

_DNS_RECV_BUFFER = 512

_QUERY_FLAGS = b'\x01\x00'
_QDCOUNT = b'\x00\x01'
_ZERO_COUNTS = b'\x00\x00\x00\x00\x00\x00'
_QTYPE_A_QCLASS_IN = b'\x00\x01\x00\x01'


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


class DnsC2BeaconExecutor:
    """Sends a single real DNS query as a jittered C2 check-in beacon.

    Distinct wire shape from the HTTP beacon (c2.py) - small periodic
    UDP/53 queries rather than TCP/80 requests - while representing the
    same post-compromise callback behavior (T1071.004).
    """

    def __init__(self, *, attack: C2DnsBeaconAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        if self._attack.jitter_seconds:
            time.sleep(random.uniform(0, self._attack.jitter_seconds))

        query_id = random.randint(0, 0xFFFF)
        message = build_dns_query(domain=self._attack.domain, query_id=query_id)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._attack.timeout_seconds)
            sock.sendto(message, (str(device.ip), self._attack.port))

            try:
                sock.recvfrom(_DNS_RECV_BUFFER)
                responded = True
            except TimeoutError:
                responded = False

        return f'beacon=sent, responded={responded}'
