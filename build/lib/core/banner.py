from core import colors

BANNER = r"""
   ░█████╗░███╗░░██╗██████╗░██████╗░
   ██╔══██╗████╗░██║██╔══██╗██╔════╝
   ███████║██╔██╗██║██║░░██║██████╗░
   ██╔══██║██║╚████║██║░░██║╚════██╗
   ██║░░██║██║░╚███║██████╔╝██████╔╝
   ╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░╚═════╝░
"""


def print_banner(version="1.0", module_count=0):
    print(f"{colors.C.GREEN}{BANNER}{colors.C.RESET}")
    print(f"  ANDS v{version} | Anomaly-based Network Detection System")
    print(f"  {module_count} modules loaded")
    print(f"  Type 'help' for commands, 'show modules' to list modules\n")