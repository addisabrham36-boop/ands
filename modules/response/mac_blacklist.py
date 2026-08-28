import subprocess
import re
from core.module_base import ModuleBase


class MACBlacklist(ModuleBase):
    """
    Layer-2 MAC Address Blacklist & Filtering Manager.
    Adds/removes Layer-2 firewall drop rules via ebtables/iptables or ARP tables
    to isolate rogue devices and malicious network adapters.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "ACTION": {"value": "block", "required": True, "desc": "Action: 'block', 'unblock', or 'list'"},
            "MAC": {"value": "", "required": False, "desc": "Target hardware MAC address (e.g. 00:11:22:33:44:55)"},
        }

    def _is_valid_mac(self, mac: str) -> bool:
        return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

    def run(self):
        action = self.options["ACTION"]["value"].lower().strip()
        mac = self.options["MAC"]["value"].strip()

        if action in ("block", "unblock") and not self._is_valid_mac(mac):
            print(f"[-] Invalid MAC address format: '{mac}'")
            return

        if action == "block":
            print(f"[*] Blocking MAC address {mac} via Layer-2 iptables filter...")
            cmd = ["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    print(f"[+] Successfully blocked MAC: {mac}")
                else:
                    print(f"[-] Error blocking MAC: {res.stderr}")
            except Exception as e:
                print(f"[-] Execution error: {e}")

        elif action == "unblock":
            print(f"[*] Unblocking MAC address {mac}...")
            cmd = ["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    print(f"[+] Successfully unblocked MAC: {mac}")
                else:
                    print(f"[-] Error unblocking MAC: {res.stderr}")
            except Exception as e:
                print(f"[-] Execution error: {e}")

        elif action == "list":
            print("[*] Inspecting active iptables MAC drop rules...")
            try:
                res = subprocess.run(["iptables", "-L", "INPUT", "-v", "-n"], capture_output=True, text=True)
                print(res.stdout)
            except Exception as e:
                print(f"[-] Could not list rules: {e}")
