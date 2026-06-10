"""
配置管理模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[新增] 支持 INI 配置文件 + 命令行参数双重配置
       配置优先级: 命令行 > 配置文件 > 默认值
"""
import configparser
import argparse
import os
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

DEFAULT_CONFIG_FILE = "scanner.cfg"

# ── 默认配置值 ────────────────────────────────────────────────
@dataclass
class ScanConfig:
    # 目标
    target:          str   = ""
    target_file:     str   = ""          # [新增] 批量扫描目标文件

    # 网络
    threads:         int   = 10
    timeout:         int   = 10
    proxy:           str   = ""
    cookie:          str   = ""
    headers:         List[str] = field(default_factory=list)
    user_agent:      str   = ""

    # [新增] 速率限制
    rate_limit:      float = 0.0         # 每次请求最小间隔秒数，0=不限制
    max_retries:     int   = 2           # 最大重试次数

    # 扫描模块开关
    modules:         List[str] = field(default_factory=list)  # 空=全部
    skip_modules:    List[str] = field(default_factory=list)
    fast_mode:       bool  = False

    # [新增] 漏洞利用开关
    exploit:         bool  = False       # 是否开启自动利用
    exploit_types:   List[str] = field(default_factory=list)  # 空=全部
    # exploit_types 可选: sqli, cmdi, xss, lfi, ssrf
    reverse_host:    str   = ""          # 反弹 Shell 监听 IP
    reverse_port:    int   = 4444        # 反弹 Shell 监听端口

    # 字典
    wordlist:        str   = ""

    # 输出
    output_json:     str   = ""
    output_html:     str   = ""
    output_csv:      str   = ""          # [新增] CSV 报告
    log_file:        str   = ""
    log_level:       str   = "INFO"
    quiet:           bool  = False       # 静默模式：只显示漏洞

    # 扫描跳过
    skip_ports:      bool  = False
    skip_dirbust:    bool  = False
    skip_sqli:       bool  = False
    skip_xss:        bool  = False
    skip_lfi:        bool  = False
    skip_subdomain:  bool  = False
    skip_bruteforce: bool  = False
    skip_upload:     bool  = False


# ── INI 文件加载 ──────────────────────────────────────────────
def load_config_file(path: str) -> dict:
    """
    [新增] 从 INI 配置文件加载配置
    """
    if not Path(path).exists():
        return {}
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    result = {}
    for section in parser.sections():
        for key, val in parser.items(section):
            result[key] = val
    return result


# ── 命令行解析 ────────────────────────────────────────────────
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webscan",
        description="WebVulnScanner v6.0 — 全功能 Web 漏洞扫描与利用框架",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="示例:\n"
               "  python main.py https://example.com\n"
               "  python main.py https://example.com --exploit --exploit-types sqli,cmdi\n"
               "  python main.py -f targets.txt --threads 20 --output-html report.html\n"
               "  python main.py https://example.com --config scanner.cfg\n"
    )

    # 目标
    tg = p.add_argument_group("目标")
    tg.add_argument("target",          nargs="?", default="", help="单个目标 URL")
    tg.add_argument("-f", "--file",    dest="target_file",    help="批量目标文件（每行一个URL）")
    tg.add_argument("-c", "--config",  default=DEFAULT_CONFIG_FILE, help="配置文件路径")

    # 网络
    ng = p.add_argument_group("网络")
    ng.add_argument("-t", "--threads", type=int,   default=10,  help="并发线程数（默认10）")
    ng.add_argument("--timeout",       type=int,   default=10,  help="超时秒数（默认10）")
    ng.add_argument("--proxy",                                   help="代理: http://127.0.0.1:8080")
    ng.add_argument("--cookie",                                  help="Cookie字符串")
    ng.add_argument("--header",        action="append", default=[], metavar="K:V")
    ng.add_argument("--user-agent",                              help="自定义 User-Agent")
    ng.add_argument("--rate-limit",    type=float, default=0.0, help="请求间隔秒数（防封IP）")
    ng.add_argument("--max-retries",   type=int,   default=2,   help="最大重试次数")

    # 漏洞利用
    eg = p.add_argument_group("漏洞利用（需 --exploit 开启）")
    eg.add_argument("--exploit",       action="store_true",     help="开启自动漏洞利用")
    eg.add_argument("--exploit-types", default="",
                    help="利用类型（逗号分隔）: sqli,cmdi,xss,lfi,ssrf\n默认全部")
    eg.add_argument("--reverse-host",                           help="反弹Shell监听IP")
    eg.add_argument("--reverse-port",  type=int,   default=4444,help="反弹Shell监听端口")

    # 模块控制
    mg = p.add_argument_group("模块控制")
    mg.add_argument("--only",          help="只运行指定模块（逗号分隔）")
    mg.add_argument("--wordlist",                                help="自定义目录字典")
    mg.add_argument("--fast",          action="store_true",     help="快速模式")
    mg.add_argument("--skip-ports",    action="store_true")
    mg.add_argument("--skip-dirbust",  action="store_true")
    mg.add_argument("--skip-sqli",     action="store_true")
    mg.add_argument("--skip-xss",      action="store_true")
    mg.add_argument("--skip-lfi",      action="store_true")
    mg.add_argument("--skip-subdomain",action="store_true")
    mg.add_argument("--skip-bruteforce",action="store_true")
    mg.add_argument("--skip-upload",   action="store_true")

    # 输出
    og = p.add_argument_group("输出")
    og.add_argument("-o", "--output-json",  help="JSON报告路径")
    og.add_argument("--output-html",        help="HTML报告路径")
    og.add_argument("--output-csv",         help="CSV报告路径")       # [新增]
    og.add_argument("--log-file",           help="日志文件路径")
    og.add_argument("--log-level",          default="INFO",
                    choices=["DEBUG","INFO","WARNING","ERROR"],
                    help="日志级别（默认INFO）")
    og.add_argument("-q", "--quiet",        action="store_true",
                    help="静默模式：只显示漏洞发现")

    return p


def parse_config(argv=None) -> ScanConfig:
    """
    [新增] 合并命令行参数 + 配置文件，返回 ScanConfig
    优先级: 命令行 > 配置文件 > 默认值
    """
    parser = build_arg_parser()
    args   = parser.parse_args(argv)
    cfg    = ScanConfig()

    # 先加载配置文件
    file_cfg = load_config_file(args.config)

    def _get(key: str, default=None):
        """命令行 > 配置文件 > default"""
        cli_val = getattr(args, key, None)
        if cli_val is not None and cli_val != default and cli_val != "" and cli_val != []:
            return cli_val
        return file_cfg.get(key, default)

    cfg.target         = args.target or file_cfg.get("target", "")
    cfg.target_file    = args.target_file or file_cfg.get("target_file", "")
    cfg.threads        = int(_get("threads", 10))
    cfg.timeout        = int(_get("timeout", 10))
    cfg.proxy          = _get("proxy", "") or ""
    cfg.cookie         = _get("cookie", "") or ""
    cfg.headers        = args.header or []
    cfg.user_agent     = _get("user_agent", "") or ""
    cfg.rate_limit     = float(_get("rate_limit", 0.0))
    cfg.max_retries    = int(_get("max_retries", 2))

    cfg.exploit        = args.exploit or str(file_cfg.get("exploit","")).lower() == "true"
    exploit_str        = args.exploit_types or file_cfg.get("exploit_types", "")
    cfg.exploit_types  = [x.strip() for x in exploit_str.split(",") if x.strip()]
    cfg.reverse_host   = _get("reverse_host", "") or ""
    cfg.reverse_port   = int(_get("reverse_port", 4444))

    only_str           = args.only or file_cfg.get("only", "")
    cfg.modules        = [x.strip() for x in only_str.split(",") if x.strip()]
    cfg.wordlist       = _get("wordlist", "") or ""
    cfg.fast_mode      = args.fast or str(file_cfg.get("fast","")).lower() == "true"

    cfg.skip_ports     = args.skip_ports
    cfg.skip_dirbust   = args.skip_dirbust
    cfg.skip_sqli      = args.skip_sqli
    cfg.skip_xss       = args.skip_xss
    cfg.skip_lfi       = args.skip_lfi
    cfg.skip_subdomain = args.skip_subdomain
    cfg.skip_bruteforce= args.skip_bruteforce
    cfg.skip_upload    = args.skip_upload

    cfg.output_json    = _get("output_json", "") or ""
    cfg.output_html    = _get("output_html", "") or ""
    cfg.output_csv     = _get("output_csv", "") or ""
    cfg.log_file       = _get("log_file", "") or ""
    cfg.log_level      = _get("log_level", "INFO")
    cfg.quiet          = args.quiet

    return cfg
