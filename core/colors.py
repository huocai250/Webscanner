"""
颜色输出与日志模块
Author: 火柴 | GitHub: huocai250
v4.0: 增加文件日志、静默模式、线程安全输出
"""
import sys
import threading
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

    _enabled = True

    @classmethod
    def strip(cls, text: str) -> str:
        """移除字符串中的 ANSI 颜色码（用于文件日志）"""
        import re
        return re.sub(r"\033\[[0-9;]*m", "", text)


ICONS = {
    "INFO": f"{Colors.BLUE}[*]{Colors.RESET}",
    "VULN": f"{Colors.RED}[!]{Colors.RESET}",
    "OK":   f"{Colors.GREEN}[+]{Colors.RESET}",
    "WARN": f"{Colors.YELLOW}[-]{Colors.RESET}",
    "SKIP": f"{Colors.DIM}[~]{Colors.RESET}",
}

# 日志级别过滤（数值越大越详细）
_LEVELS = {"VULN": 0, "WARN": 1, "OK": 2, "INFO": 3, "SKIP": 3}

_print_lock = threading.Lock()
_log_file = None          # 文件句柄
_verbosity = 3            # 默认显示全部
_quiet = False            # 静默：仅错误/漏洞


def configure(log_path: str | None = None, verbosity: int = 3, quiet: bool = False,
              no_color: bool = False):
    """初始化日志系统"""
    global _log_file, _verbosity, _quiet
    _verbosity = verbosity
    _quiet = quiet
    if no_color or not sys.stdout.isatty():
        # 关闭颜色（重定向到文件/管道时）
        for attr in ("RED", "GREEN", "YELLOW", "BLUE", "PURPLE",
                     "CYAN", "WHITE", "RESET", "BOLD", "DIM"):
            setattr(Colors, attr, "")
        _rebuild_icons()
    if log_path:
        _log_file = open(log_path, "a", encoding="utf-8")


def _rebuild_icons():
    ICONS.update({
        "INFO": f"{Colors.BLUE}[*]{Colors.RESET}",
        "VULN": f"{Colors.RED}[!]{Colors.RESET}",
        "OK":   f"{Colors.GREEN}[+]{Colors.RESET}",
        "WARN": f"{Colors.YELLOW}[-]{Colors.RESET}",
        "SKIP": f"{Colors.DIM}[~]{Colors.RESET}",
    })


def close():
    global _log_file
    if _log_file:
        _log_file.close()
        _log_file = None


def log(level: str, msg: str):
    if _quiet and level not in ("VULN", "WARN"):
        return
    if _LEVELS.get(level, 3) > _verbosity:
        return
    ts = datetime.now().strftime("%H:%M:%S")
    icon = ICONS.get(level, "[?]")
    line = f"{Colors.DIM}[{ts}]{Colors.RESET} {icon} {msg}"
    with _print_lock:
        print(line)
        if _log_file:
            _log_file.write(Colors.strip(f"[{ts}] [{level}] {msg}") + "\n")
            _log_file.flush()


def raw(msg: str = ""):
    """打印原始文本（不带时间戳/图标），仍受静默控制。"""
    if _quiet:
        return
    with _print_lock:
        print(msg)
        if _log_file:
            _log_file.write(Colors.strip(msg) + "\n")


def banner():
    if _quiet:
        return
    print(f"""{Colors.CYAN}{Colors.BOLD}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.RESET}
  {Colors.BOLD}Web Vulnerability Scanner v8.0{Colors.RESET}  {Colors.DIM}(26 检测模块){Colors.RESET}
  {Colors.DIM}Author : {Colors.CYAN}火柴{Colors.RESET}
  {Colors.DIM}GitHub : {Colors.CYAN}https://github.com/huocai250{Colors.RESET}
  {Colors.DIM}Warning: 仅供授权渗透测试与安全研究使用{Colors.RESET}
""")
