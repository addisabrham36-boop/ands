import cmd
from modules.system.selftest import SelfTest
from modules.generate.synthetic import SyntheticTraffic
from core.session import Session
from modules.detect.zscore_anomaly import ZScoreAnomaly
from modules.detect.portscan_detect import PortScanDetect
from modules.capture.traffic_baseline import TrafficBaseline
from modules.report.generate_report import ReportGenerator
from core.module_loader import load_custom_modules


class ANDSConsole(cmd.Cmd):
    intro = "\nANDS v1.0 | type 'help' for commands, 'show modules' to list modules\n"
    prompt = "ands > "

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.modules = {
            "capture/baseline": TrafficBaseline,
            "detect/zscore": ZScoreAnomaly,
            "detect/portscan": PortScanDetect,
            "report/generate": ReportGenerator,
            "generate/synthetic": SyntheticTraffic,
            "system/selftest": SelfTest,
        }
        self.modules.update(load_custom_modules())
        self.active_module = None
        self.active_path = None

    def do_setg(self, arg):
        """setg <option> <value>  — set a global option, persists across all modules"""
        try:
            key, value = arg.split(maxsplit=1)
            self.session.set_global(key, value)
            print(f"[+] GLOBAL {key.upper()} => {value}")
        except ValueError:
            print("[-] Usage: setg <option> <value>")
    def do_use(self, arg):
        """use <module_path>  — select a module, e.g. use detect/zscore"""
        arg = arg.strip()
        if arg in self.modules:
            self.active_module = self.modules[arg](self.session)
            self.active_path = arg
            self.prompt = f"ands ({arg}) > "
            print(f"[+] Loaded module: {arg}")
        else:
            print(f"[-] No such module: {arg}")
            print("[*] Available:", ", ".join(self.modules.keys()))

    def do_show(self, arg):
        """show options | show modules  — show config or list modules"""
        arg = arg.strip()
        if arg == "options":
            if self.active_module:
                self.active_module.show_options()
            else:
                print("[-] No module selected.")
        elif arg == "modules":
            for i, m in enumerate(self.modules, 1):
                print(f"  [{i}] {m}")
        else:
            print("[-] Usage: show options | show modules")

    def do_set(self, arg):
        """set <option> <value>  — configure the active module"""
        try:
            key, value = arg.split(maxsplit=1)
            self.active_module.set_option(key, value)
        except (ValueError, AttributeError):
            print("[-] Usage: set <option> <value>  (load a module first with 'use')")

    def do_run(self, arg):
        """run  — execute the active module"""
        if not self.active_module:
            print("[-] No module selected. Use 'use <module_path>' first.")
            return
        missing = self.active_module.missing_required()
        if missing:
            print(f"[-] Missing required options: {', '.join(missing)}")
            return
        try:
            self.active_module.run()
        except PermissionError:
            print("[-] Permission denied. Try running with sudo.")
        except KeyboardInterrupt:
            print("\n[*] Interrupted.")
        except Exception as e:
            print(f"[-] Module error: {e}")

    def do_back(self, arg):
        """back  — deselect current module"""
        self.active_module = None
        self.active_path = None
        self.prompt = "ands > "
    def do_uniq(self, arg):
        """uniq  — summarize this session's alerts, collapsing duplicates by source"""
        alerts = self.session.alert_history
        if not alerts:
            print("[*] No alerts recorded this session.")
            return

        summary = {}
        for a in alerts:
            key = a.get("source") or f"window-{a.get('window', '?')}"
            summary.setdefault(key, {"count": 0, "type": a["type"]})
            summary[key]["count"] += 1

        total = len(alerts)
        print(f"[*] {total} alerts collapsed into {len(summary)} unique source(s):")
        for key, info in sorted(summary.items(), key=lambda x: -x[1]["count"]):
            print(f"    {key:<20} x{info['count']:<4} ({info['type']})")

    def do_reload(self, arg):
        """reload  — rescan modules/custom/ for new user-added modules"""
        new_modules = load_custom_modules()
        self.modules.update(new_modules)
        print(f"[*] Reloaded. {len(self.modules)} total module(s) available.")

    def do_exit(self, arg):
        """exit  — quit ANDS"""
        print("[*] Exiting ANDS.")
        return True

    do_quit = do_exit

    def emptyline(self):
        pass  # don't repeat last command on blank Enter


if __name__ == "__main__":
    ANDSConsole().cmdloop()