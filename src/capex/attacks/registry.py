from __future__ import annotations

from typing import TYPE_CHECKING

from capex.attacks.application_layer import HttpFuzzExecutor
from capex.attacks.arp import ArpSpoofExecutor
from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.c2 import C2BeaconExecutor
from capex.attacks.c2_dns import DnsC2BeaconExecutor
from capex.attacks.credential_access import HydraBruteForceExecutor
from capex.attacks.discovery import BannerGrabExecutor, SsdpDiscoveryExecutor
from capex.attacks.exfil import ExfilSimExecutor
from capex.attacks.exfil_dns import DnsTunnelExfilExecutor
from capex.attacks.hulk import HulkAttackExecutor
from capex.attacks.impact import ConfigTamperExecutor
from capex.exceptions import RegistryError

if TYPE_CHECKING:
    from capex.attacks.base import BoundAttackExecutor
    from capex.models import AttackConfig
    from capex.runner import CommandRunner


class AttackRegistry:
    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def resolve(self, attack: AttackConfig) -> BoundAttackExecutor:
        match attack.kind:
            case 'command':
                return CommandAttackExecutor(
                    runner=self._runner,
                    attack=attack,
                )
            case 'placeholder':
                return PlaceholderAttackExecutor(
                    attack=attack,
                )
            case 'hulk':
                return HulkAttackExecutor(
                    attack=attack,
                )
            case 'ssdp_discovery':
                return SsdpDiscoveryExecutor(
                    attack=attack,
                )
            case 'banner_grab':
                return BannerGrabExecutor(
                    attack=attack,
                )
            case 'hydra_brute_force':
                return HydraBruteForceExecutor(
                    runner=self._runner,
                    attack=attack,
                )
            case 'http_fuzz':
                return HttpFuzzExecutor(
                    attack=attack,
                )
            case 'c2_beacon':
                return C2BeaconExecutor(
                    attack=attack,
                )
            case 'c2_dns_beacon':
                return DnsC2BeaconExecutor(
                    attack=attack,
                )
            case 'exfil_sim':
                return ExfilSimExecutor(
                    attack=attack,
                )
            case 'config_tamper':
                return ConfigTamperExecutor(
                    attack=attack,
                )
            case 'arp_spoof':
                return ArpSpoofExecutor(
                    runner=self._runner,
                    attack=attack,
                )
            case 'dns_tunnel_exfil':
                return DnsTunnelExfilExecutor(
                    attack=attack,
                )
            case _:
                msg = f'Unsupported attack kind: {attack.kind}'
                raise RegistryError(msg)
