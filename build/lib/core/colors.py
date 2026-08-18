class C:
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"


def error(msg):
    print(f"{C.RED}[-] {msg}{C.RESET}")


def warn(msg):
    print(f"{C.YELLOW}[!] {msg}{C.RESET}")


def success(msg):
    print(f"{C.GREEN}[+] {msg}{C.RESET}")


def info(msg):
    print(f"{C.BLUE}[*] {msg}{C.RESET}")


def alert(msg):
    print(f"{C.RED}{C.BOLD}[ALERT]{C.RESET} {msg}")