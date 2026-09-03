from __future__ import annotations

from ipaddress import IPv4Address

from capex.models import CommandAttackConfig, DeviceConfig, HydraBruteForceAttackConfig


def test_device_config_validates() -> None:
    device = DeviceConfig(name='nestCam', ip=IPv4Address('192.168.1.196'))
    assert device.name == 'nestCam'


def test_attack_config_validates() -> None:
    attack = CommandAttackConfig(
        name='udp_flood',
        label='UDP_Flood',
        command=['hping3', '--udp', '-c', '100', '-p', '53', '{target_ip}'],
    )
    assert attack.repeats == 3


def test_hydra_brute_force_attack_config_defaults() -> None:
    attack = HydraBruteForceAttackConfig(
        name='hydra_http_default_creds',
        label='Hydra_HTTP_Default_Creds',
        service='http-get',
        port=80,
        username_list=['admin'],
        password_list=['admin'],
    )
    assert attack.max_attempts == 10
    assert attack.tasks == 1
