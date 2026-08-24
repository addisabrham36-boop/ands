from core.module_base import ModuleBase
import subprocess
import os


class IPTablesBlock(ModuleBase):
    """
    Active Response & Firewall Mitigation Engine.
    Executes automated or operator-directed iptables / nftables firewall rules
    to drop malicious traffic from high-confidence attacker IPs instantly.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "ACTION": {"value": "list", "required": True, "desc": "block | unblock | list"},
            "TARGET_IP": {"value": "", "required": False, "desc": "Attacker IP address to block or unblock"},
        }

    def _execute_cmd(self, cmd_args):
        try:
            res = subprocess.run(cmd_args, capture_output=True, text=True)
            return res.returncode == 0, res.stdout, res.stderr
        except Exception as e:
            return False, "", str(e)

    def block_ip(self, ip: str) -> bool:
        if not ip or ip in ("127.0.0.1", "0.0.0.0", "::1"):
            print(f"[-] Refusing to block local / loopback IP: {ip}")
            return False
        
        # iptables -I INPUT -s <IP> -j DROP
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        ok, out, err = self._execute_cmd(cmd)
        if ok:
            self.session.banned_ips.add(ip)
            print(f"[+] Successfully blocked {ip} via iptables DROP rule.")
            return True
        else:
            print(f"[-] Failed to block {ip}: {err.strip() or 'Permission denied'}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        ok, out, err = self._execute_cmd(cmd)
        if ok:
            self.session.banned_ips.discard(ip)
            print(f"[+] Successfully unblocked {ip} from iptables.")
            return True
        else:
            print(f"[-] Failed to unblock {ip}: {err.strip() or 'Rule not found'}")
            return False

    def list_blocks(self):
        cmd = ["sudo", "iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"]
        ok, out, err = self._execute_cmd(cmd)
        if ok:
            print(f"\n[*] Active iptables INPUT Firewall Rules:\n")
            print(out)
        else:
            print(f"[-] Unable to list iptables rules: {err.strip()}")
            if self.session.banned_ips:
                print(f"[*] In-memory tracked blocked IPs: {', '.join(sorted(self.session.banned_ips))}")

    def run(self):
        action = self.options["ACTION"]["value"].lower().strip()
        target = self.options["TARGET_IP"]["value"].strip()

        if action == "block":
            if not target:
                print("[-] TARGET_IP is required for 'block' action.")
                return
            self.block_ip(target)
        elif action == "unblock":
            if not target:
                print("[-] TARGET_IP is required for 'unblock' action.")
                return
            self.unblock_ip(target)
        elif action == "list":
            self.list_blocks()
        else:
            print(f"[-] Unknown ACTION: {action}. Use 'block', 'unblock', or 'list'.")
