import cmd
from modules.generate.synthetic import SyntheticTraffic
from core.session import Session
from modules.detect.zscore_anomaly import ZScoreAnomaly
from modules.detect.portscan_detect import PortScanDetect
from modules.capture.traffic_baseline import TrafficBaseline
from modules.report.generate_report import ReportGenerator


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
        }
        self.active_module = None
        self.active_path = None

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
            for m in self.modules:
                print(f"  {m}")
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

    def do_exit(self, arg):
        """exit  — quit ANDS"""
        print("[*] Exiting ANDS.")
        return True

    do_quit = do_exit

    def emptyline(self):
        pass  # don't repeat last command on blank Enter


if __name__ == "__main__":
    ANDSConsole().cmdloop()

