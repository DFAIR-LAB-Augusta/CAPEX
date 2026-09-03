from __future__ import annotations

import socket

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import DeviceConfig, HttpFuzzAttackConfig

_RECV_BUFFER = 1024


class HttpFuzzExecutor:
    """Sends malformed/fuzzed and traversal HTTP requests to a device's web UI."""

    def __init__(self, *, attack: HttpFuzzAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        host = str(device.ip)
        response_count = 0

        for path in self._attack.paths:
            request = f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode()

            try:
                sock = socket.create_connection((host, self._attack.port), timeout=self._attack.timeout_seconds)
            except OSError:
                continue

            with sock:
                sock.settimeout(self._attack.timeout_seconds)
                sock.sendall(request)
                try:
                    data = sock.recv(_RECV_BUFFER)
                except TimeoutError:
                    data = b''

            if data:
                response_count += 1

        return f'requests={len(self._attack.paths)}, responses={response_count}'
