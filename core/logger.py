"""
统一日志模块 — WebVulnScanner v7.0
Author: 火柴 | GitHub: huocai250

[优化] 使用 logging 模块替代 print，支持文件+终端双输出
       支持日志级别控制、时间戳、颜色
"""
import logging
import sys
from pathlib import Path
from datetime import datetime

# ── ANSI 颜色 ──────────────────────────────────────────────────
class C:
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

# ── 彩色终端 Formatter ─────────────────────────────────────────
class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG:    C.DIM,
        logging.INFO:     C.BLUE,
        logging.WARNING:  C.YELLOW,
        logging.ERROR:    C.RED,
        logging.CRITICAL: C.RED + C.BOLD,
    }
    ICONS = {
        logging.DEBUG:    "[~]",
        logging.INFO:     "[*]",
        logging.WARNING:  "[-]",
        logging.ERROR:    "[!]",
        logging.CRITICAL: "[!]",
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelno, C.RESET)
        icon  = self.ICONS.get(record.levelno, "[?]")
        ts    = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        msg   = record.getMessage()
        return f"{C.DIM}[{ts}]{C.RESET} {color}{icon}{C.RESET} {msg}"


# ── 文件 Formatter（无颜色）──────────────────────────────────
class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts  = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        lvl = record.levelname[:5].ljust(5)
        return f"[{ts}] [{lvl}] {record.getMessage()}"


# ── 特殊级别：VULN（漏洞发现）────────────────────────────────
VULN_LEVEL = 35   # 介于 WARNING(30) 和 ERROR(40) 之间
logging.addLevelName(VULN_LEVEL, "VULN")

def _vuln(self: logging.Logger, msg: str, *args, **kwargs):
    if self.isEnabledFor(VULN_LEVEL):
        self._log(VULN_LEVEL, msg, args, **kwargs)

logging.Logger.vuln = _vuln  # type: ignore


class VulnColorFormatter(ColorFormatter):
    """扩展：VULN 级别显示红色感叹号"""
    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == VULN_LEVEL:
            ts  = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            return (f"{C.DIM}[{ts}]{C.RESET} "
                    f"{C.RED}{C.BOLD}[VULN]{C.RESET} "
                    f"{C.RED}{record.getMessage()}{C.RESET}")
        return super().format(record)


# ── 工厂函数 ──────────────────────────────────────────────────
def setup_logger(
    name:       str  = "webscan",
    level:      str  = "INFO",
    log_file:   str  = None,
) -> logging.Logger:
    """
    [优化] 统一日志初始化入口
    - level: DEBUG / INFO / WARNING / ERROR
    - log_file: 若指定则同时写入文件
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)          # logger 本身接收所有级别
    logger.handlers.clear()

    # 数值化级别
    numeric = getattr(logging, level.upper(), logging.INFO)

    # 终端 handler
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(numeric)
    sh.setFormatter(VulnColorFormatter())
    logger.addHandler(sh)

    # 文件 handler（可选）
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)          # 文件记录全部
        fh.setFormatter(PlainFormatter())
        logger.addHandler(fh)

    return logger


# 全局默认 logger（各模块直接 import 使用）
logger = setup_logger()


def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}
  {C.BOLD}Web Vulnerability Scanner  v7.0{C.RESET}
  {C.DIM}Author : {C.CYAN}火柴{C.RESET}
  {C.DIM}GitHub : {C.CYAN}https://github.com/huocai250{C.RESET}
  {C.YELLOW}  ⚠  仅供授权渗透测试与安全研究使用{C.RESET}
""")
