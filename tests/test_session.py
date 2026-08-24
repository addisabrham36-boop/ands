from core.session import Session


def test_session_alert_enrichment():
    session = Session()
    alert = session.add_alert({
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "confidence": 0.85,
        "source": "192.168.1.100",
        "destination": "192.168.1.1",
        "description": "Port scan probe",
    })
    
    assert alert["id"] is not None
    assert alert["mitre_id"] == "T1046"
    assert len(session.alert_history) == 1
    assert session.alert_history[0]["source"] == "192.168.1.100"


def test_session_whitelist_false_positive_suppression():
    session = Session()
    session.add_whitelist("10.0.0.50")
    
    # Whitelisted alert should be suppressed
    alert_result = session.add_alert({
        "type": "PORT_SCAN",
        "source": "10.0.0.50",
        "destination": "10.0.0.1",
    })
    assert alert_result == {}
    assert len(session.alert_history) == 0


def test_session_network_inventory():
    session = Session()
    session.record_host("192.168.1.5", mac="00:0c:29:11:22:33", vendor="VMware", os_hint="Linux", port=80, proto="HTTP")
    session.record_host("192.168.1.5", port=443, proto="TLS")
    
    inventory = session.get_inventory()
    assert len(inventory) == 1
    host = inventory[0]
    assert host["ip"] == "192.168.1.5"
    assert host["vendor"] == "VMware"
    assert 80 in host["ports"]
    assert 443 in host["ports"]


def test_session_traffic_history():
    session = Session()
    session.record_traffic_point(pps=45.2, bps=102400.0, zscore_val=1.2)
    assert len(session.traffic_history) == 1
    point = session.traffic_history[0]
    assert point["pps"] == 45.2
    assert point["zscore"] == 1.2
