"""
颜色输出与日志模块
Author: 火柴 | GitHub: huocai250
"""
from datetime import datetime


class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"


ICONS = {
    "INFO": f"{Colors.BLUE}[*]{Colors.RESET}",
    "VULN": f"{Colors.RED}[!]{Colors.RESET}",
    "OK":   f"{Colors.GREEN}[+]{Colors.RESET}",
    "WARN": f"{Colors.YELLOW}[-]{Colors.RESET}",
    "SKIP": f"{Colors.DIM}[~]{Colors.RESET}",
}


def log(level: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    icon = ICONS.get(level, "[?]")
    print(f"{Colors.DIM}[{ts}]{Colors.RESET} {icon} {msg}")


def banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.RESET}
  {Colors.BOLD}Web Vulnerability Scanner v4.0{Colors.RESET}
  {Colors.DIM}Author : {Colors.CYAN}火柴{Colors.RESET}
  {Colors.DIM}GitHub : {Colors.CYAN}https://github.com/huocai250{Colors.RESET}
  {Colors.DIM}Warning: 仅供授权渗透测试与安全研究使用{Colors.RESET}
""")
