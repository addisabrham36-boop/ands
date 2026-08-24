from core.session import Session
from core.module_loader import load_all_modules


def test_module_loader_discovery():
    modules = load_all_modules()
    assert len(modules) >= 30

    expected_modules = [
        "detect/portscan",
        "detect/zscore",
        "detect/synflood",
        "detect/arpspoof",
        "detect/dns_tunnel",
        "detect/beaconing",
        "detect/bruteforce",
        "detect/icmp_tunnel",
        "detect/http_anomaly",
        "detect/slowloris",
        "detect/land_smurf",
        "detect/dhcp_rogue",
        "detect/threat_intel",
        "detect/ntp_amplification",
        "detect/ssdp_amplification",
        "detect/dns_amplification",
        "detect/smb_anomaly",
        "detect/snmp_bruteforce",
        "detect/ip_fragmentation",
        "detect/packet_fuzzing",
        "audit/cleartext_creds",
        "audit/network_inventory",
        "audit/ssl_tls",
        "audit/dns_resolver",
        "capture/traffic_baseline",
        "capture/flow_analyzer",
        "capture/live_stream",
        "generate/synthetic",
        "generate/dns_payload",
        "generate/arp_payload",
        "generate/c2_beacon_payload",
        "generate/ntp_monlist_payload",
        "generate/http_bench_payload",
        "generate/ssdp_probe_payload",
        "generate/snmp_test_payload",
        "generate/fragmented_payload",
        "response/iptables_block",
        "response/pcap_extractor",
        "report/generate_report",
        "report/json_export",
        "system/selftest",
        "system/interface_info",
    ]

    for m in expected_modules:
        assert m in modules, f"Expected module {m} not discovered by module loader"


def test_selftest_module_execution():
    session = Session()
    modules = load_all_modules()
    selftest_cls = modules["system/selftest"]
    instance = selftest_cls(session)
    instance.run()
