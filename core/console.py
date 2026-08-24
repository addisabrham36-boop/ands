import cmd
import os
import sys
import subprocess
import threading
import time
import warnings

# Suppress cryptography / scapy deprecation warnings
warnings.filterwarnings("ignore")

from core import colors
from core.banner import print_banner
from core.session import Session
from core.engine import LiveEngine
from core.module_loader import load_all_modules


class ANDSConsole(cmd.Cmd):
    prompt = f"{colors.C.BOLD}{colors.C.WHITE}ands{colors.C.RESET} {colors.C.GRAY}❯{colors.C.RESET} "
    SAFE_SHELL_COMMANDS = {"ls", "cat", "pwd", "clear", "grep", "head", "tail", "whoami", "date", "ip", "ifconfig", "ping"}

    def default(self, line):
        cmd_word = line.split()[0] if line.split() else ""
        if cmd_word in self.SAFE_SHELL_COMMANDS:
            subprocess.run(line, shell=True)
        else:
            colors.error(f"Unknown command: '{cmd_word}'. Type 'help' for available commands.")

    def __init__(self, session=None, engine=None):
        super().__init__()
        self.session = session or Session()
        self.engine = engine or LiveEngine(self.session)
        self.modules = load_all_modules()
        self.active_module = None
        self.active_path = None
        self.background_jobs = {}
        self.job_counter = 1

    def complete_use(self, text, line, begidx, endidx):
        return [m for m in self.modules.keys() if m.startswith(text)]

    def complete_show(self, text, line, begidx, endidx):
        options = ["options", "modules", "alerts", "inventory", "stats", "jobs"]
        return [o for o in options if o.startswith(text)]

    def do_banner(self, arg):
        """banner  — display ANDS ASCII banner"""
        print_banner(version="2.0.0", module_count=len(self.modules))

    def do_setg(self, arg):
        """setg <option> <value>  — set a global option (e.g. setg INTERFACE enp1s0)"""
        try:
            key, value = arg.split(maxsplit=1)
            self.session.set_global(key, value)
            colors.success(f"GLOBAL {key.upper()} => {value}")
        except ValueError:
            colors.error("Usage: setg <option> <value>")

    def do_use(self, arg):
        """use <module_path>  — select a module (e.g. use detect/portscan)"""
        arg = arg.strip()
        if arg in self.modules:
            self.active_module = self.modules[arg](self.session)
            self.active_path = arg
            self.prompt = f"{colors.C.BOLD}{colors.C.WHITE}ands{colors.C.RESET} ({colors.C.SILVER}{arg}{colors.C.RESET}) {colors.C.GRAY}❯{colors.C.RESET} "
            colors.success(f"Loaded module: {arg}")
        else:
            colors.error(f"No such module: {arg}")
            print(f"{colors.C.GRAY}[*] Try 'show modules' or 'search <term>'{colors.C.RESET}")

    def do_search(self, arg):
        """search <term>  — find modules matching a keyword"""
        term = arg.strip().lower()
        if not term:
            colors.error("Usage: search <term>")
            return
        matches = [m for m in sorted(self.modules.keys()) if term in m.lower()]
        if matches:
            colors.info(f"{len(matches)} matching module(s):")
            for m in matches:
                print(f"  • {m}")
        else:
            colors.info(f"No modules matching '{term}'")

    def do_show(self, arg):
        """show [options|modules|alerts|inventory|stats|jobs]"""
        arg = arg.strip().lower()
        c = colors.C

        if arg == "options":
            if self.active_module:
                self.active_module.show_options()
            else:
                colors.error("No module selected. Use 'use <module>' first.")

        elif arg == "modules":
            print(f"\n{c.BOLD}{c.WHITE}┌── ANDS MODULE REGISTRY ({len(self.modules)} Loaded Modules/Aliases) {'─'*25}┐{c.RESET}")
            print(f"{c.GRAY}│ {'#':<3} {'MODULE PATH':<34} {'CATEGORY':<14} │{c.RESET}")
            print(f"{c.GRAY}├{'─'*58}┤{c.RESET}")
            categories = ["detect", "audit", "capture", "generate", "response", "report", "system", "custom"]
            idx = 1
            for cat in categories:
                cat_mods = sorted([m for m in self.modules.keys() if m.startswith(f"{cat}/") and not m.endswith("_detect") and not m.endswith("_audit") and not m.endswith("_payload") and not m.endswith("_anomaly")])
                for m in cat_mods:
                    print(f"{c.GRAY}│{c.RESET} {idx:<3} {c.WHITE}{m:<34}{c.RESET} {c.SILVER}{cat.upper():<14}{c.RESET} {c.GRAY}│{c.RESET}")
                    idx += 1
            print(f"{c.GRAY}└{'─'*58}┘{c.RESET}\n")

        elif arg == "alerts":
            self.do_alerts("")

        elif arg == "inventory":
            self.do_inventory("")

        elif arg == "stats":
            self.do_stats("")

        elif arg == "jobs":
            self.do_jobs("")

        else:
            colors.error("Usage: show [options|modules|alerts|inventory|stats|jobs]")

    def do_set(self, arg):
        """set <option> <value>  — configure active module option"""
        try:
            key, value = arg.split(maxsplit=1)
            if self.active_module:
                self.active_module.set_option(key, value)
            else:
                colors.error("No module selected. Use 'use <module>' first.")
        except ValueError:
            colors.error("Usage: set <option> <value>")

    def do_run(self, arg):
        """run [-bg]  — execute the active module (use -bg for background thread)"""
        if not self.active_module:
            colors.error("No module selected. Use 'use <module>' first.")
            return

        missing = self.active_module.missing_required()
        if missing:
            colors.error(f"Missing required options: {', '.join(missing)}")
            return

        is_bg = "-bg" in arg

        if is_bg:
            job_id = self.job_counter
            self.job_counter += 1
            mod_copy = self.modules[self.active_path](self.session)
            for k, v in self.active_module.options.items():
                mod_copy.options[k]["value"] = v["value"]

            def bg_runner():
                try:
                    mod_copy.run()
                except Exception as e:
                    colors.error(f"Background Job #{job_id} error: {e}")

            t = threading.Thread(target=bg_runner, daemon=True, name=f"Job-{job_id}-{self.active_path}")
            t.start()
            self.background_jobs[job_id] = {"name": self.active_path, "thread": t, "start": time.time()}
            colors.success(f"Launched Job #{job_id} [{self.active_path}] in background.")
        else:
            try:
                self.active_module.run()
            except PermissionError:
                colors.error("Permission denied. Try running with sudo.")
            except KeyboardInterrupt:
                colors.info("Module execution interrupted.")
            except Exception as e:
                colors.error(f"Module error: {e}")

    def do_back(self, arg):
        """back  — return to top-level prompt"""
        self.active_module = None
        self.active_path = None
        self.prompt = f"{colors.C.BOLD}{colors.C.WHITE}ands{colors.C.RESET} {colors.C.GRAY}❯{colors.C.RESET} "

    def do_live(self, arg):
        """live [start|stop|status|view] [interface]  — manage continuous live packet engine"""
        parts = arg.strip().split()
        subcmd = parts[0].lower() if parts else "status"
        c = colors.C

        if subcmd == "start":
            iface = parts[1] if len(parts) > 1 else self.session.get_global("INTERFACE", "enp1s0")
            if self.engine.is_running():
                colors.warn(f"Live Engine is already running on {self.engine.interface}")
                return
            ok = self.engine.start(interface=iface)
            if ok:
                colors.success(f"Live Sentinel started on {iface}")
            else:
                colors.error("Failed to start Live Engine.")

        elif subcmd == "stop":
            if not self.engine.is_running():
                colors.info("Live Engine is not running.")
                return
            self.engine.stop()
            colors.success("Live Sentinel stopped.")

        elif subcmd in ("view", "monitor"):
            self._live_terminal_hud()

        elif subcmd == "status":
            stats = self.engine.get_stats()
            state_str = f"{c.BOLD}{c.WHITE}[RUNNING]{c.RESET}" if stats["running"] else f"{c.GRAY}[STOPPED]{c.RESET}"
            print(f"\n{c.BOLD}{c.WHITE}┌── ANDS LIVE SENTINEL TELEMETRY {'─'*32}┐{c.RESET}")
            print(f"{c.GRAY}│{c.RESET}  State:             {state_str}")
            print(f"{c.GRAY}│{c.RESET}  Interface:         {c.WHITE}{stats['interface']}{c.RESET}")
            print(f"{c.GRAY}│{c.RESET}  Uptime:            {stats['uptime_seconds']}s")
            print(f"{c.GRAY}│{c.RESET}  Packets Captured:  {c.BOLD}{c.WHITE}{stats['total_packets']}{c.RESET}")
            print(f"{c.GRAY}│{c.RESET}  Throughput:        {stats['current_pps']} pkt/s ({stats['current_kbps']} KB/s)")
            print(f"{c.GRAY}│{c.RESET}  Baseline Median:   {stats['baseline_median_pps']} pkt/s (MAD)")
            print(f"{c.GRAY}│{c.RESET}  Total Alerts:      {c.BOLD}{c.WHITE}{stats['alerts_count']}{c.RESET}")
            print(f"{c.GRAY}│{c.RESET}  Discovered Hosts:  {stats['hosts_discovered']}")
            print(f"{c.GRAY}└{'─'*65}┘\n")
        else:
            colors.error("Usage: live [start|stop|status|view] [interface]")

    def _live_terminal_hud(self):
        """Dynamic full-screen terminal live monitoring HUD."""
        c = colors.C
        if not self.engine.is_running():
            self.engine.start()

        print(f"{c.BOLD}{c.WHITE}[*] Entering Live Sentinel Monitor Mode. Press Ctrl+C to exit.{c.RESET}")
        time.sleep(0.5)

        try:
            while True:
                stats = self.engine.get_stats()
                alerts = self.session.alert_history[-5:]
                proto = self.session.protocol_stats
                total_p = sum(proto.values()) or 1

                os.system("clear")
                print(f"{c.BOLD}{c.WHITE}══════════════════════════════════════════════════════════════════════════════{c.RESET}")
                print(f" {c.BOLD}{c.WHITE}ANDS LIVE SOC SENTINEL HUD{c.RESET}  |  Interface: {c.WHITE}{stats['interface']}{c.RESET}  |  Time: {time.strftime('%H:%M:%S')}")
                print(f"{c.GRAY}──────────────────────────────────────────────────────────────────────────────{c.RESET}")
                print(f" Throughput: {c.BOLD}{c.WHITE}{stats['current_pps']} pps{c.RESET} ({stats['current_kbps']} KB/s) | Baseline: {stats['baseline_median_pps']} pps | Packets: {stats['total_packets']}")
                print(f" Alerts Logged: {c.BOLD}{c.WHITE}{len(self.session.alert_history)}{c.RESET} | Discovered Hosts: {stats['hosts_discovered']} | Uptime: {stats['uptime_seconds']}s")
                print(f"{c.GRAY}──────────────────────────────────────────────────────────────────────────────{c.RESET}")

                print(f"{c.BOLD}PROTOCOL BREAKDOWN:{c.RESET}")
                for p_name in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"):
                    cnt = proto.get(p_name, 0)
                    pct = (cnt / total_p) * 100
                    bar = "█" * int(pct // 4)
                    print(f"  {p_name:<6} {cnt:<7} ({pct:<5.1f}%) | {bar}")

                print(f"\n{c.BOLD}RECENT THREAT ALERTS (Last 5):{c.RESET}")
                if alerts:
                    for a in alerts:
                        sev = a.get("severity", "MED")
                        sev_badge = f"{c.INVERT} {sev} {c.RESET}" if sev == "CRITICAL" else f"{c.BOLD}[{sev}]{c.RESET}"
                        print(f"  {a.get('timestamp', '')[11:]} {sev_badge} {a.get('type', '')[:20]:<20} {a.get('source', 'N/A')} -> {a.get('destination', 'N/A')}")
                else:
                    print(f"  {c.GRAY}No security threats detected. Wire is quiet.{c.RESET}")

                print(f"{c.GRAY}══════════════════════════════════════════════════════════════════════════════{c.RESET}")
                print(f"  {c.GRAY}Press Ctrl+C to return to console.{c.RESET}")
                time.sleep(1.0)

        except KeyboardInterrupt:
            os.system("clear")
            colors.info("Exited Live Monitor HUD.")

    def do_dashboard(self, arg):
        """dashboard [port]  — launch the SOC Analyst Web Dashboard server"""
        port = int(arg.strip()) if arg.strip().isdigit() else 8899
        try:
            from web.server import start_dashboard_server
            colors.success(f"Starting ANDS SOC Web Dashboard on http://localhost:{port}...")
            start_dashboard_server(self.session, self.engine, port=port, open_browser=True)
        except Exception as e:
            colors.error(f"Dashboard error: {e}")

    def do_app(self, arg):
        """app  — launch standalone Arch Linux Desktop App window"""
        try:
            subprocess.Popen(["/home/abrham/ands/bin/ands-app"])
            colors.success("Launched ANDS Desktop Application.")
        except Exception as e:
            colors.error(f"App launch error: {e}")

    def do_alerts(self, arg):
        """alerts [limit]  — view recorded security alerts"""
        limit = int(arg.strip()) if arg.strip().isdigit() else 25
        alerts = self.session.get_alerts(limit=limit)
        c = colors.C
        if not alerts:
            colors.info("No alerts recorded yet.")
            return

        print(f"\n{c.BOLD}{c.WHITE}┌── RECORDED SECURITY ALERTS ({len(alerts)} displayed) {'─'*35}┐{c.RESET}")
        print(f"{c.GRAY}│ {'TIME':<9} {'SEV':<10} {'TYPE':<22} {'MITRE':<8} {'SOURCE':<16} {'TARGET':<16} │{c.RESET}")
        print(f"{c.GRAY}├{'─'*85}┤{c.RESET}")
        for a in alerts:
            sev = a.get("severity", "MEDIUM")
            sev_badge = f"{c.INVERT}{sev[:8]:<9}{c.RESET}" if sev == "CRITICAL" else (
                f"{c.BOLD}{sev[:8]:<9}{c.RESET}" if sev == "HIGH" else f"{c.GRAY}{sev[:8]:<9}{c.RESET}"
            )
            print(f"{c.GRAY}│{c.RESET} {a.get('timestamp', '')[11:]: <9} {sev_badge} {a.get('type', '')[:21]:<22} {a.get('mitre_id', 'N/A'):<8} {a.get('source', '')[:15]:<16} {a.get('destination', '')[:15]:<16} {c.GRAY}│{c.RESET}")
        print(f"{c.GRAY}└{'─'*85}┘\n")

    def do_inventory(self, arg):
        """inventory  — view discovered network devices and asset fingerprints"""
        inv = self.session.get_inventory()
        c = colors.C
        print(f"\n{c.BOLD}{c.WHITE}┌── DISCOVERED ASSET INVENTORY ({len(inv)} Hosts) {'─'*35}┐{c.RESET}")
        print(f"{c.GRAY}│ {'IP ADDRESS':<17} {'MAC ADDRESS':<18} {'VENDOR':<18} {'OS HINT':<12} {'ALERTS':<6} │{c.RESET}")
        print(f"{c.GRAY}├{'─'*77}┤{c.RESET}")
        for h in inv:
            print(f"{c.GRAY}│{c.RESET} {c.BOLD}{h['ip']:<17}{c.RESET} {h['mac'] or 'N/A':<18} {h['vendor'] or 'Unknown':<18} {h['os_hint'] or 'Unknown':<12} {h['alerts']:<6} {c.GRAY}│{c.RESET}")
        print(f"{c.GRAY}└{'─'*77}┘\n")

    def do_stats(self, arg):
        """stats  — display live protocol telemetry breakdown"""
        stats = self.session.protocol_stats
        total = sum(stats.values()) or 1
        c = colors.C
        print(f"\n{c.BOLD}{c.WHITE}┌── PROTOCOL TELEMETRY BREAKDOWN ({total} Total Packets) {'─'*22}┐{c.RESET}")
        for proto, count in stats.items():
            pct = (count / total) * 100
            bar = "█" * int(pct // 4)
            print(f"{c.GRAY}│{c.RESET} {proto:<8} {count:<8} ({pct:<5.1f}%) | {c.WHITE}{bar}{c.RESET}")
        print(f"{c.GRAY}└{'─'*65}┘\n")

    def do_whitelist(self, arg):
        """whitelist [add|remove|list] <ip>  — manage false-positive suppression whitelist"""
        parts = arg.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else "list"
        ip = parts[1].strip() if len(parts) > 1 else ""

        if sub == "add" and ip:
            self.session.add_whitelist(ip)
            colors.success(f"Added {ip} to whitelist.")
        elif sub == "remove" and ip:
            self.session.remove_whitelist(ip)
            colors.success(f"Removed {ip} from whitelist.")
        elif sub == "list" or not parts:
            print(f"[*] Whitelisted IPs (Suppressed from alerts): {', '.join(sorted(self.session.whitelist))}")
        else:
            colors.error("Usage: whitelist [add|remove|list] <ip>")

    def do_block(self, arg):
        """block <ip>  — active response: block attacker IP via iptables firewall"""
        ip = arg.strip()
        if not ip:
            colors.error("Usage: block <ip>")
            return
        from modules.response.iptables_block import IPTablesBlock
        mod = IPTablesBlock(self.session)
        mod.block_ip(ip)

    def do_unblock(self, arg):
        """unblock <ip>  — unblock IP from iptables firewall"""
        ip = arg.strip()
        if not ip:
            colors.error("Usage: unblock <ip>")
            return
        from modules.response.iptables_block import IPTablesBlock
        mod = IPTablesBlock(self.session)
        mod.unblock_ip(ip)

    def do_jobs(self, arg):
        """jobs  — list active background jobs"""
        active = {jid: j for jid, j in self.background_jobs.items() if j["thread"].is_alive()}
        self.background_jobs = active
        c = colors.C
        if not active:
            colors.info("No active background jobs.")
            return
        print(f"\n{c.BOLD}{c.WHITE}┌── ACTIVE BACKGROUND JOBS ({len(active)}) {'─'*30}┐{c.RESET}")
        for jid, j in active.items():
            elapsed = int(time.time() - j["start"])
            print(f"{c.GRAY}│{c.RESET} [Job #{jid}] {j['name']:<30} Elapsed: {elapsed}s")
        print(f"{c.GRAY}└{'─'*55}┘\n")

    def do_uniq(self, arg):
        """uniq  — summarize session alerts grouped by source"""
        alerts = self.session.alert_history
        if not alerts:
            colors.info("No alerts recorded this session.")
            return

        summary = {}
        for a in alerts:
            key = a.get("source") or "UNKNOWN"
            summary.setdefault(key, {"count": 0, "types": set()})
            summary[key]["count"] += 1
            summary[key]["types"].add(a.get("type", "UNKNOWN"))

        colors.info(f"{len(alerts)} alerts aggregated across {len(summary)} unique source(s):")
        for key, info in sorted(summary.items(), key=lambda x: -x[1]["count"]):
            types_str = ", ".join(info["types"])
            print(f"    {key:<22} x{info['count']:<4} ({types_str})")

    def do_reload(self, arg):
        """reload  — rescan modules directory for new modules"""
        self.modules = load_all_modules()
        colors.success(f"Reloaded module registry: {len(self.modules)} total modules/aliases available.")

    def do_clear(self, arg):
        """clear  — clear terminal screen"""
        os.system("clear")

    def do_help(self, arg):
        """help  — display structured command help"""
        c = colors.C
        print(f"\n{c.BOLD}{c.WHITE}ANDS COMMAND REFERENCE & QUICK START{c.RESET}")
        print(f"{c.GRAY}{'─'*65}{c.RESET}")
        print(f" {c.BOLD}Module Execution:{c.RESET}")
        print(f"   use <module>        Select module (e.g. use detect/portscan)")
        print(f"   set <opt> <val>     Configure module option")
        print(f"   setg <opt> <val>    Set persistent global setting")
        print(f"   run [-bg]           Execute active module (-bg for background)")
        print(f"   show <target>       Show options, modules, alerts, inventory, stats, jobs")
        print(f"   search <term>       Search module catalog by keyword")
        print(f"   back                Deselect current module\n")

        print(f" {c.BOLD}Live Sentinel & Monitoring:{c.RESET}")
        print(f"   live start [iface]  Start background packet detection engine")
        print(f"   live stop           Stop background packet engine")
        print(f"   live status         Check live engine counters & throughput")
        print(f"   live view           Full-screen dynamic terminal live monitor HUD")
        print(f"   dashboard [port]    Launch Cyber SOC Analyst Web UI (port 8899)")
        print(f"   app                 Launch Arch Linux standalone Desktop App\n")

        print(f" {c.BOLD}Response & Security Controls:{c.RESET}")
        print(f"   alerts [limit]      Browse recent threat alerts")
        print(f"   inventory           Inspect discovered network assets")
        print(f"   whitelist <ip>      Add/remove IP from false-positive whitelist")
        print(f"   block <ip>          Active Response: drop attacker IP via iptables")
        print(f"   unblock <ip>        Remove iptables drop rule")
        print(f"   stats               Display protocol telemetry breakdown")
        print(f"   uniq                Aggregate alerts by source")
        print(f"   clear / exit        Clear screen / Quit ANDS\n")

    def do_exit(self, arg):
        """exit  — shutdown and quit ANDS"""
        if self.engine.is_running():
            self.engine.stop()
        colors.info("Exiting ANDS Sentinel. Stay secure!")
        return True

    do_quit = do_exit

    def emptyline(self):
        pass


def main():
    session = Session()
    engine = LiveEngine(session)

    if len(sys.argv) > 1:
        cmd_arg = sys.argv[1].lower()
        if cmd_arg in ("dashboard", "web", "gui"):
            port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8899
            from web.server import start_dashboard_server
            engine.start()
            start_dashboard_server(session, engine, port=port, open_browser=True)
            return
        elif cmd_arg in ("live", "monitor"):
            iface = sys.argv[2] if len(sys.argv) > 2 else "enp1s0"
            engine.start(interface=iface)
            console = ANDSConsole(session, engine)
            console._live_terminal_hud()
            return

    console = ANDSConsole(session, engine)
    print_banner(version="2.0.0", module_count=len(console.modules))
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        if engine.is_running():
            engine.stop()
        print("\n[*] Force quit — exiting ANDS.")


if __name__ == "__main__":
    main()