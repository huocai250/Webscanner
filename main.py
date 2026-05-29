#!/usr/bin/env python3
"""
WebVulnScanner v4.0 — 全功能 Web 漏洞扫描工具
Author : 火柴
GitHub : https://github.com/huocai250
Warning: 仅供授权渗透测试与安全研究使用，未经授权扫描属于违法行为！
"""
import sys
import os
import time
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from core.colors  import banner, log, Colors
from core.result  import ScanResult
from utils.http   import parse_cookies
from utils.report import print_terminal, save_json, save_html

from modules.info           import InfoGatherer
from modules.headers        import HeaderChecker
from modules.ssl_check      import SSLChecker
from modules.sensitive      import SensitiveInfoScanner
from modules.csrf           import CSRFScanner
from modules.cors           import CORSScanner
from modules.sqli           import SQLiScanner
from modules.xss            import XSSScanner
from modules.lfi            import LFIScanner
from modules.redirect       import OpenRedirectScanner
from modules.ports          import PortScanner
from modules.dirbust        import DirBuster
from modules.xxe            import XXEScanner
from modules.ssrf           import SSRFScanner
from modules.subdomain      import SubdomainScanner
from modules.jwt_check      import JWTScanner
from modules.http_methods   import HTTPMethodScanner
from modules.file_upload    import FileUploadScanner
from modules.weak_creds     import WeakCredScanner
from modules.clickjacking   import ClickjackingScanner
from modules.path_traversal import PathTraversalScanner
from modules.api_security   import APIScanner
from modules.injections     import InjectionScanner


def parse_args():
    parser = argparse.ArgumentParser(
        prog="webscanner",
        description="WebVulnScanner v4.0 — 仅供授权渗透测试使用",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",           help="目标 URL，例如 https://example.com")
    parser.add_argument("-t", "--threads",  type=int, default=10, help="并发线程数（默认10）")
    parser.add_argument("--timeout",        type=int, default=10, help="超时秒数（默认10）")
    parser.add_argument("--cookie",         help="Cookie: key=val;key2=val2")
    parser.add_argument("--header",         action="append", default=[], metavar="K:V")
    parser.add_argument("--proxy",          help="代理: http://127.0.0.1:8080")
    parser.add_argument("--wordlist",       help="自定义目录字典路径")
    parser.add_argument("-o", "--output",   help="JSON 报告路径")
    parser.add_argument("--html",           help="HTML 报告路径")

    # 快速 / 跳过
    parser.add_argument("--fast",           action="store_true", help="快速模式（跳过耗时模块）")
    parser.add_argument("--skip-ports",     action="store_true")
    parser.add_argument("--skip-dirbust",   action="store_true")
    parser.add_argument("--skip-sqli",      action="store_true")
    parser.add_argument("--skip-xss",       action="store_true")
    parser.add_argument("--skip-lfi",       action="store_true")
    parser.add_argument("--skip-subdomain", action="store_true")
    parser.add_argument("--skip-bruteforce",action="store_true")
    parser.add_argument("--skip-upload",    action="store_true")

    # 单模块运行
    parser.add_argument("--only",           help="只运行指定模块，逗号分隔\n"
        "可选: info,headers,ssl,sensitive,cors,csrf,sqli,xss,lfi,redirect,\n"
        "      ports,dirbust,xxe,ssrf,subdomain,jwt,methods,upload,\n"
        "      creds,clickjacking,traversal,api,injections")
    return parser.parse_args()


def build_kw(args):
    cookies = parse_cookies(args.cookie) if args.cookie else {}
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return dict(timeout=args.timeout, threads=args.threads,
                cookies=cookies, headers=headers, proxy=args.proxy)


def main():
    banner()
    args = parse_args()

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    print(f"{Colors.YELLOW}{'─'*65}")
    print(f"  ⚠  警告：本工具仅供已获授权的渗透测试使用")
    print(f"      未经书面授权扫描他人系统属于违法行为！")
    print(f"{'─'*65}{Colors.RESET}\n")
    time.sleep(1)

    log("INFO", f"目标  : {Colors.CYAN}{Colors.BOLD}{target}{Colors.RESET}")
    log("INFO", f"线程  : {args.threads} | 超时: {args.timeout}s | 代理: {args.proxy or '无'}")
    log("INFO", f"时间  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("INFO", f"作者  : 火柴 | GitHub: https://github.com/huocai250")
    print()

    result = ScanResult(target)
    kw = build_kw(args)
    fast = args.fast
    only = set(args.only.split(",")) if args.only else None

    def mk(cls, **extra):
        return cls(target, result, **{**kw, **extra})

    # (name_key, label, module, skip_condition)
    plan = [
        ("info",        "信息收集 & WAF",   mk(InfoGatherer),                   False),
        ("headers",     "HTTP 安全头",       mk(HeaderChecker),                  False),
        ("ssl",         "SSL/TLS",           mk(SSLChecker),                     False),
        ("sensitive",   "敏感信息泄露",      mk(SensitiveInfoScanner),           False),
        ("cors",        "CORS 配置",         mk(CORSScanner),                    False),
        ("csrf",        "CSRF",              mk(CSRFScanner),                    False),
        ("clickjacking","Clickjacking & 配置错误", mk(ClickjackingScanner),      False),
        ("methods",     "危险 HTTP 方法",    mk(HTTPMethodScanner),              False),
        ("redirect",    "开放重定向",        mk(OpenRedirectScanner),            False),
        ("jwt",         "JWT 安全",          mk(JWTScanner),                     False),
        ("injections",  "Log4Shell/Host Header/CRLF", mk(InjectionScanner),     False),
        ("api",         "API 安全",          mk(APIScanner),                     False),
        ("sqli",        "SQL 注入",          mk(SQLiScanner),                    args.skip_sqli),
        ("xss",         "XSS & SSTI",        mk(XSSScanner),                     args.skip_xss),
        ("lfi",         "LFI & 命令注入",    mk(LFIScanner),                     args.skip_lfi or fast),
        ("traversal",   "路径穿越",          mk(PathTraversalScanner),           fast),
        ("xxe",         "XXE 注入",          mk(XXEScanner),                     fast),
        ("ssrf",        "SSRF",              mk(SSRFScanner),                    fast),
        ("upload",      "文件上传漏洞",      mk(FileUploadScanner),              args.skip_upload or fast),
        ("creds",       "弱口令检测",        mk(WeakCredScanner),                args.skip_bruteforce or fast),
        ("subdomain",   "子域名枚举",        mk(SubdomainScanner),               args.skip_subdomain or fast),
        ("ports",       "端口扫描",          mk(PortScanner),                    args.skip_ports or fast),
        ("dirbust",     "目录枚举",          mk(DirBuster, wordlist_file=args.wordlist),
                                                                                args.skip_dirbust or fast),
    ]

    for key, label, module, skip in plan:
        if only and key not in only:
            continue
        if skip:
            log("SKIP", f"跳过模块: {label}")
            continue
        print(f"\n{Colors.PURPLE}{'─'*55}{Colors.RESET}")
        log("INFO", f"▶ 模块: {Colors.BOLD}{label}{Colors.RESET}")
        try:
            module.run()
        except KeyboardInterrupt:
            log("WARN", "用户中断，生成当前报告...")
            break
        except Exception as e:
            log("WARN", f"模块 [{label}] 异常: {e}")

    # 报告
    print(f"\n{Colors.PURPLE}{'═'*55}{Colors.RESET}")
    print_terminal(result)

    if args.output:
        save_json(result, args.output)

    html_path = args.html or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    save_html(result, html_path)

    counts = result.summary()
    print(f"\n{Colors.BOLD}扫描完成！"
          f"CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} "
          f"MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']}{Colors.RESET}")


if __name__ == "__main__":
    main()
