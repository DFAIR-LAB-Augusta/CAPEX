from __future__ import annotations

import socket

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import ConfigTamperAttackConfig, DeviceConfig

_RECV_BUFFER = 1024


class ConfigTamperExecutor:
    """Sends a real config/firmware-tampering-shaped request and reports the response status.

    Defaults to enabled: false at the model level - each entry needs
    per-device safety vetting before it is turned on, since a payload
    that actually succeeds could brick real lab hardware (see #80).
    """

    def __init__(self, *, attack: ConfigTamperAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        host = str(device.ip)
        body = self._attack.body.format(target_ip=host).encode()

        headers = f'Content-Type: {self._attack.content_type}\r\n'
        if self._attack.soap_action:
            headers += f'SOAPAction: "{self._attack.soap_action}"\r\n'

        request = (
            f'{self._attack.method} {self._attack.path} HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'{headers}'
            f'Content-Length: {len(body)}\r\n'
            'Connection: close\r\n\r\n'
        ).encode() + body

        try:
            sock = socket.create_connection((host, self._attack.port), timeout=self._attack.timeout_seconds)
        except OSError:
            return 'response=<unreachable>'

        with sock:
            sock.settimeout(self._attack.timeout_seconds)
            sock.sendall(request)
            try:
                data = sock.recv(_RECV_BUFFER)
            except TimeoutError:
                return 'response=<no response>'

        status_line = data.split(b'\r\n', 1)[0].decode('utf-8', errors='replace').strip()
        return f'response={status_line!r}'
