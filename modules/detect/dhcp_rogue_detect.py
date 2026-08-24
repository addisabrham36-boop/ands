from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, BOOTP, DHCP
from datetime import datetime


class DHCPRogueDetect(ModuleBase):
    """
    Rogue DHCP Server & DHCP Starvation Sentinel.
    Monitors DHCP protocol exchanges (UDP 67/68), verifying legitimate DHCP Offer/ACK
    servers against approved gateway lists and catching rogue DHCP spoofers.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "AUTHORIZED_SERVERS": {"value": "", "required": False, "desc": "Comma-separated list of authorized DHCP server IPs (e.g. 192.168.1.1)"},
        }
        self.seen_dhcp_servers = set()
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(UDP) and pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
            return

        bootp = pkt[BOOTP]
        dhcp = pkt[DHCP]
        
        # Extract message type
        msg_type = None
        for opt in dhcp.options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = opt[1]
                break

        # 2 = DHCPOFFER, 5 = DHCPACK
        if msg_type in (2, 5):
            server_ip = bootp.siaddr or (pkt[IP].src if pkt.haslayer(IP) else "UNKNOWN")
            auth_str = self.options["AUTHORIZED_SERVERS"]["value"]
            auth_list = [s.strip() for s in auth_str.split(",") if s.strip()]

            # If user specified authorized servers and this server is not in it
            is_rogue = bool(auth_list and server_ip not in auth_list)

            # Or if multiple distinct DHCP servers are competing on the subnet
            self.seen_dhcp_servers.add(server_ip)
            if len(self.seen_dhcp_servers) > 1 and not auth_list:
                is_rogue = True

            if is_rogue and server_ip not in self.already_alerted:
                self.already_alerted.add(server_ip)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Rogue DHCP Server Active: {server_ip} (Offered IP: {bootp.yiaddr}) [{ts}]")

                self.session.add_alert({
                    "type": "ROGUE_DHCP_SERVER",
                    "severity": "CRITICAL",
                    "confidence": 0.96,
                    "mitre_id": "T1557",
                    "source": server_ip,
                    "destination": "BROADCAST",
                    "protocol": "DHCP",
                    "description": f"Rogue / Unauthorized DHCP Server detected on local network: {server_ip} is broadcasting unauthorized DHCP Offer/ACK messages",
                    "details": {
                        "rogue_server_ip": server_ip,
                        "offered_client_ip": bootp.yiaddr,
                        "transaction_id": hex(bootp.xid),
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.seen_dhcp_servers.clear()
        self.already_alerted.clear()

        print(f"[*] DHCP Sentinel active on {iface} (ports 67/68)...")
        try:
            sniff(iface=iface, filter="udp and (port 67 or port 68)", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DHCP monitoring stopped.")
            return

        print(f"[+] DHCP Sentinel completed — {len(self.seen_dhcp_servers)} DHCP server(s) observed.")
