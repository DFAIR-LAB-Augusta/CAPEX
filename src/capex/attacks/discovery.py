from __future__ import annotations

import socket

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import BannerGrabAttackConfig, DeviceConfig, SsdpDiscoveryAttackConfig

_SSDP_PORT = 1900
_SSDP_RECV_BUFFER = 4096
_BANNER_RECV_BUFFER = 1024
_BANNER_TRUNCATE_LENGTH = 200


def _build_msearch(mx_seconds: int) -> bytes:
    return (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        f'MX: {mx_seconds}\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    ).encode()


class SsdpDiscoveryExecutor:
    """Sends a unicast SSDP M-SEARCH probe directly to the target device."""

    def __init__(self, *, attack: SsdpDiscoveryAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        message = _build_msearch(self._attack.timeout_seconds)
        response_count = 0

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._attack.timeout_seconds)
            sock.sendto(message, (str(device.ip), _SSDP_PORT))

            while True:
                try:
                    sock.recvfrom(_SSDP_RECV_BUFFER)
                except TimeoutError:
                    break
                else:
                    response_count += 1

        return f'responses={response_count}'


class BannerGrabExecutor:
    """Connects to a device port and reports whatever banner it sends back."""

    def __init__(self, *, attack: BannerGrabAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        try:
            sock = socket.create_connection(
                (str(device.ip), self._attack.port),
                timeout=self._attack.timeout_seconds,
            )
        except OSError:
            return 'banner=<connection failed>'

        with sock:
            sock.settimeout(self._attack.timeout_seconds)
            if self._attack.probe:
                probe = self._attack.probe.format(target_ip=str(device.ip)).encode()
                sock.sendall(probe)

            try:
                data = sock.recv(_BANNER_RECV_BUFFER)
            except TimeoutError:
                return 'banner=<no response>'

        banner = data.decode('utf-8', errors='replace').strip()
        return f'banner={banner[:_BANNER_TRUNCATE_LENGTH]!r}'
