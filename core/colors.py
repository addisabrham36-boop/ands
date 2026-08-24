class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    INVERT = "\033[7m"

    # Monochrome High Contrast Palette
    WHITE = "\033[97m"
    SILVER = "\033[37m"
    GRAY = "\033[90m"
    BLACK = "\033[30m"

    # Accent Highlights
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"


def error(msg: str):
    print(f"{C.BOLD}{C.WHITE}[✗]{C.RESET} {C.SILVER}{msg}{C.RESET}")


def warn(msg: str):
    print(f"{C.BOLD}{C.WHITE}[!]{C.RESET} {C.SILVER}{msg}{C.RESET}")


def success(msg: str):
    print(f"{C.BOLD}{C.WHITE}[✓]{C.RESET} {C.SILVER}{msg}{C.RESET}")


def info(msg: str):
    print(f"{C.BOLD}{C.WHITE}[*]{C.RESET} {C.SILVER}{msg}{C.RESET}")


def alert(msg: str):
    print(f"{C.INVERT}{C.BOLD} ALERT {C.RESET} {C.BOLD}{C.WHITE}{msg}{C.RESET}")


def print_divider(char="─", length=78):
    print(f"{C.GRAY}{char * length}{C.RESET}")


def print_header(title: str, subtitle: str = ""):
    print(f"\n{C.BOLD}{C.WHITE}┌─ {title.upper()} {'─' * max(2, 70 - len(title))}┐{C.RESET}")
    if subtitle:
        print(f"{C.GRAY}│  {subtitle}{C.RESET}")
        print(f"{C.GRAY}├{'─' * 74}┤{C.RESET}")