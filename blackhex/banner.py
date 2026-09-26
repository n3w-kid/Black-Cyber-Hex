import os

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
PURPLE = "\033[38;5;93m"
MAGENTA = "\033[38;5;129m"
GRAY = "\033[38;5;240m"
RED = "\033[38;5;160m"

ART = r"""
        ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
        ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
        ██████╔╝██║     ███████║██║     █████╔╝
        ██╔══██╗██║     ██╔══██║██║     ██╔═██╗
        ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
        ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

              C Y B E R   H E X
              ─────────────────
             WEB SECURITY FRAMEWORK
              ⬢  ◈  ⬢  ◈  ⬢  ◈
"""


def banner() -> None:
    color = os.getenv("NO_COLOR") is None
    if color:
        print(f"{DIM}{GRAY}┌──────────────────────────────────────────────────────────────┐{RESET}")
        for line in ART.strip("\n").splitlines():
            if "CYBER" in line or "WEB SECURITY" in line:
                print(f"{BOLD}{MAGENTA}{line}{RESET}")
            else:
                print(f"{PURPLE}{line}{RESET}")
        print(f"{DIM}{GRAY}└──────────────────────────────────────────────────────────────┘{RESET}")
        print(f"{RED}  [ authorized security testing only ]{RESET}\n")
    else:
        print(ART)
        print("  [ authorized security testing only ]\n")
