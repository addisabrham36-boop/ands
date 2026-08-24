from core import colors


BANNER_LOGO = r"""
 █████╗ ███╗   ██╗██████╗ ███████╗
██╔══██╗████╗  ██║██╔══██╗██╔════╝
███████║██╔██╗ ██║██║  ██║███████╗
██╔══██║██║╚██╗██║██║  ██║╚════██║
██║  ██║██║ ╚████║██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝
"""


def print_banner(version="2.0.0", module_count=0):
    c = colors.C
    print(f"{c.BOLD}{c.WHITE}{BANNER_LOGO}{c.RESET}")
    print(f"{c.GRAY}┌────────────────────────────────────────────────────────────────────────┐{c.RESET}")
    print(f"{c.GRAY}│{c.RESET}  {c.BOLD}{c.WHITE}ANDS SENTINEL v{version}{c.RESET} — Anomaly-based Network Detection & SOC Auditor {c.GRAY}│{c.RESET}")
    print(f"{c.GRAY}│{c.RESET}  {c.WHITE}[{module_count} Modules Loaded]{c.RESET}  •  Live Engine  •  Web SOC (8899)  •  Arch Desktop {c.GRAY}│{c.RESET}")
    print(f"{c.GRAY}└────────────────────────────────────────────────────────────────────────┘{c.RESET}")
    print(f"  {c.GRAY}Type {c.WHITE}'help'{c.GRAY} for commands, {c.WHITE}'show modules'{c.GRAY} to list modules, {c.WHITE}'dashboard'{c.GRAY} for Web UI.{c.RESET}\n")