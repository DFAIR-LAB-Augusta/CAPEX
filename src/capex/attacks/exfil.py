from __future__ import annotations

import os
import socket

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import DeviceConfig, ExfilSimAttackConfig

_RECV_BUFFER = 1024


class ExfilSimExecutor:
    """Sends a bulk outbound POST burst, simulating data-staging/exfil traffic."""

    def __init__(self, *, attack: ExfilSimAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        host = str(device.ip)
        header = (
            f'POST {self._attack.path} HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            'Content-Type: application/octet-stream\r\n'
            f'Content-Length: {self._attack.payload_size_bytes}\r\n'
            'Connection: close\r\n\r\n'
        ).encode()

        try:
            sock = socket.create_connection((host, self._attack.port), timeout=self._attack.timeout_seconds)
        except OSError:
            return 'bytes_sent=0'

        bytes_sent = 0
        with sock:
            sock.settimeout(self._attack.timeout_seconds)
            try:
                sock.sendall(header)

                remaining = self._attack.payload_size_bytes
                while remaining > 0:
                    chunk_len = min(self._attack.chunk_size_bytes, remaining)
                    sock.sendall(os.urandom(chunk_len))
                    bytes_sent += chunk_len
                    remaining -= chunk_len
            except OSError:
                pass
            else:
                try:
                    sock.recv(_RECV_BUFFER)
                except TimeoutError:
                    pass

        return f'bytes_sent={bytes_sent}'
