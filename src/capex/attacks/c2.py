from __future__ import annotations

import random
import socket
import time

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import C2BeaconAttackConfig, DeviceConfig

_BEACON_USER_AGENT = 'capex-c2-sim/1.0'
_RECV_BUFFER = 1024


class C2BeaconExecutor:
    """Sends a single jittered check-in request, mimicking botnet C2 beaconing.

    Each invocation sends one beacon; repeats/scheduling spread beacons
    across the capture window to produce a periodic-with-jitter traffic
    pattern representing post-compromise callback behavior.
    """

    def __init__(self, *, attack: C2BeaconAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        if self._attack.jitter_seconds:
            time.sleep(random.uniform(0, self._attack.jitter_seconds))

        host = str(device.ip)
        request = (
            f'GET {self._attack.path} HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'User-Agent: {_BEACON_USER_AGENT}\r\n'
            'Connection: close\r\n\r\n'
        ).encode()

        try:
            sock = socket.create_connection((host, self._attack.port), timeout=self._attack.timeout_seconds)
        except OSError:
            return 'beacon=<unreachable>'

        with sock:
            sock.settimeout(self._attack.timeout_seconds)
            sock.sendall(request)
            try:
                sock.recv(_RECV_BUFFER)
            except TimeoutError:
                pass

        return 'beacon=sent'
