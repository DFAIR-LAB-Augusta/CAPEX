from __future__ import annotations

from ipaddress import IPv4Address

from capex.models import (
    ArpSpoofAttackConfig,
    BannerGrabAttackConfig,
    C2BeaconAttackConfig,
    C2DnsBeaconAttackConfig,
    CommandAttackConfig,
    DeviceConfig,
    DnsTunnelExfilAttackConfig,
    ExfilSimAttackConfig,
    HttpFuzzAttackConfig,
    HydraBruteForceAttackConfig,
    SsdpDiscoveryAttackConfig,
)


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


def test_ssdp_discovery_attack_config_defaults() -> None:
    attack = SsdpDiscoveryAttackConfig(name='ssdp_discovery', label='SSDP_Discovery')
    assert attack.timeout_seconds == 3


def test_banner_grab_attack_config_defaults() -> None:
    attack = BannerGrabAttackConfig(name='banner_grab', label='Banner_Grab')
    assert attack.port == 80
    assert attack.probe == ''


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


def test_http_fuzz_attack_config_defaults() -> None:
    attack = HttpFuzzAttackConfig(
        name='http_fuzz',
        label='HTTP_Fuzz',
        paths=['/../../../../etc/passwd'],
    )
    assert attack.port == 80
    assert attack.timeout_seconds == 5


def test_c2_beacon_attack_config_defaults() -> None:
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon')
    assert attack.jitter_seconds == 5
    assert attack.path == '/'


def test_c2_dns_beacon_attack_config_defaults() -> None:
    attack = C2DnsBeaconAttackConfig(name='c2_dns_beacon', label='C2_DNS_Beacon')
    assert attack.port == 53
    assert attack.domain == 'update-check.example'


def test_exfil_sim_attack_config_defaults() -> None:
    attack = ExfilSimAttackConfig(name='exfil_sim', label='Exfil_Sim')
    assert attack.payload_size_bytes == 1_000_000
    assert attack.chunk_size_bytes == 65_536


def test_arp_spoof_attack_config_defaults() -> None:
    attack = ArpSpoofAttackConfig(name='arp_spoof', label='ARP_Spoof', interface='eth0', gateway_ip='192.168.1.1')
    assert attack.duration_seconds == 30
    assert attack.arpspoof_binary == 'arpspoof'


def test_dns_tunnel_exfil_attack_config_defaults() -> None:
    attack = DnsTunnelExfilAttackConfig(name='dns_tunnel_exfil', label='DNS_Tunnel_Exfil')
    assert attack.payload_size_bytes == 512
    assert attack.base_domain == 'exfil.example'
