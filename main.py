#!/usr/bin/env python3
"""
WebVulnScanner v11.0 — 全功能 Web 漏洞扫描工具
Author : 火柴
GitHub : https://github.com/huocai250
Warning: 仅供授权渗透测试与安全研究使用，未经授权扫描属于违法行为！

定位：检测/评估型扫描器 —— 探测漏洞是否存在并给出整改建议，
      不包含利用/提权/数据窃取/持久化等攻击功能。
"""
import os
import re
import sys
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import colors
from core.colors import banner, log, raw, Colors
from core.config import ScanConfig
from core.engine import run_scan, display_name, DISPLAY
from core.configfile import load_config_file
from core.batch import run_batch, load_targets
from utils.http import parse_cookies
from utils.report import (print_terminal, save_json, save_html,
                          save_markdown, save_csv)


def parse_args():
    p = argparse.ArgumentParser(
        prog="webscanner",
        description="WebVulnScanner v11.0 — 仅供授权渗透测试使用",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="目标 URL，例如 https://example.com")

    net = p.add_argument_group("网络")
    net.add_argument("-t", "--threads", type=int, help="并发线程数（默认 10）")
    net.add_argument("--timeout", type=float, help="请求超时秒数（默认 10）")
    net.add_argument("--retries", type=int, help="失败重试次数（默认 2）")
    net.add_argument("--cookie", help="Cookie 字符串: key=val;key2=val2")
    net.add_argument("--header", action="append", default=[], metavar="K:V",
                     help="自定义请求头，可多次")
    net.add_argument("--proxy", help="代理地址，如 http://127.0.0.1:8080")
    net.add_argument("--random-agent", action="store_true", help="每请求随机 UA")
    net.add_argument("--verify-ssl", action="store_true", help="校验 TLS 证书")

    rate = p.add_argument_group("频率控制（负责任扫描）")
    rate.add_argument("--delay", type=float, help="每请求延迟秒数")
    rate.add_argument("--jitter", type=float, help="附加随机抖动秒数")
    rate.add_argument("--rate", type=float, help="全局最大请求数/秒（0=不限）")

    crawl = p.add_argument_group("爬虫")
    crawl.add_argument("--no-crawl", action="store_true", help="禁用爬虫")
    crawl.add_argument("--max-urls", type=int, help="最多爬取页面数（默认 100）")
    crawl.add_argument("--max-depth", type=int, help="爬取深度（默认 2）")
    crawl.add_argument("--max-requests", type=int, metavar="N",
                       help="请求总预算上限（0=不限制），控制扫描开销")

    scope = p.add_argument_group("作用域与模式")
    scope.add_argument("--scope", action="append", default=[], metavar="HOST",
                       help="允许扫描的主机(后缀)，可多次；默认锁定目标主机")
    scope.add_argument("--passive", action="store_true", help="被动模式（非侵入式）")
    scope.add_argument("--canary", help="带外探测 canary 域名（Log4Shell/SSRF）")
    scope.add_argument("--wordlist", help="自定义目录字典")
    scope.add_argument("--subdomain-wordlist", help="自定义子域名字典")
    scope.add_argument("--plugins", metavar="DIR", help="插件目录（热加载自定义模块）")
    scope.add_argument("--templates", metavar="DIR", help="额外 YAML 模板目录（追加签名规则）")

    out = p.add_argument_group("输出")
    out.add_argument("-o", "--output", help="JSON 报告")
    out.add_argument("--html", help="HTML 报告")
    out.add_argument("--md", help="Markdown 报告")
    out.add_argument("--csv", help="CSV 报告")
    out.add_argument("--log", help="日志文件")
    out.add_argument("--auto-report", action="store_true", help="未指定输出时自动存 HTML")
    out.add_argument("-q", "--quiet", action="store_true", help="静默（仅漏洞/警告）")
    out.add_argument("--no-color", action="store_true", help="关闭彩色输出")

    ctl = p.add_argument_group("模块控制")
    ctl.add_argument("--skip", action="append", default=[], metavar="MODULE",
                     help=f"跳过模块，可多次: {', '.join(DISPLAY)}")
    ctl.add_argument("--fast", action="store_true",
                     help="快速模式（跳过端口/目录/LFI/子域名/Log4Shell）")

    misc = p.add_argument_group("运行模式")
    misc.add_argument("--config", metavar="FILE", help="从 scanner.cfg 读取默认参数")
    misc.add_argument("-f", "--targets", metavar="FILE", help="批量扫描目标文件（每行一个）")
    misc.add_argument("--concurrency", type=int, default=3, help="批量扫描并发目标数（默认 3）")
    misc.add_argument("--web", action="store_true", help="启动 Web UI（Flask）")
    misc.add_argument("-y", "--yes", action="store_true", help="跳过授权确认（自动化用）")

    return p.parse_args()


def build_config(args, target: str) -> ScanConfig:
    # 1) 起点：默认值
    cfg = ScanConfig(target=target)

    # 2) 配置文件覆盖
    if args.config:
        try:
            for k, v in load_config_file(args.config).items():
                setattr(cfg, k, v)
        except Exception as e:
            log("WARN", f"配置文件加载失败: {e}")

    # 3) 命令行覆盖（仅当显式给出）
    def ov(attr, val):
        if val is not None:
            setattr(cfg, attr, val)

    ov("threads", args.threads); ov("timeout", args.timeout); ov("retries", args.retries)
    ov("proxy", args.proxy); ov("delay", args.delay); ov("jitter", args.jitter)
    ov("rate", args.rate); ov("max_urls", args.max_urls); ov("max_depth", args.max_depth)
    ov("canary", args.canary); ov("wordlist_file", args.wordlist)
    ov("subdomain_wordlist", args.subdomain_wordlist); ov("plugins_dir", args.plugins)
    ov("templates_dir", args.templates); ov("max_requests", args.max_requests)
    ov("json_out", args.output); ov("html_out", args.html); ov("md_out", args.md)
    ov("csv_out", args.csv); ov("log_out", args.log)

    if args.random_agent: cfg.random_agent = True
    if args.verify_ssl:   cfg.verify_ssl = True
    if args.no_crawl:     cfg.crawl = False
    if args.passive:      cfg.passive = True
    if args.auto_report:  cfg.auto_report = True
    if args.scope:        cfg.scope = args.scope
    if args.cookie:       cfg.cookies = parse_cookies(args.cookie)
    if args.header:
        hdrs = dict(cfg.headers)
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                hdrs[k.strip()] = v.strip()
        cfg.headers = hdrs

    # skip 集合
    skip = set(cfg.skip) | {s.strip().lower() for s in args.skip}
    if args.fast:
        skip |= {"ports", "dirbust", "lfi", "subdomain", "log4shell"}
    cfg.skip = skip
    return cfg


def authorize(target: str, assume_yes: bool) -> bool:
    raw(f"{Colors.YELLOW}{'─'*65}")
    raw("  ⚠  警告：本工具仅供授权渗透测试使用")
    raw("      未经目标系统书面授权，扫描行为属于违法行为！")
    raw(f"{'─'*65}{Colors.RESET}")
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return True
    try:
        ans = input(f"  确认已获得对 {target} 的书面授权？[y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


def save_reports(cfg: ScanConfig, result, suffix: str = ""):
    def path(base):
        if not base or not suffix:
            return base
        stem, ext = os.path.splitext(base)
        return f"{stem}_{suffix}{ext}"
    if cfg.json_out: save_json(result, path(cfg.json_out))
    if cfg.html_out: save_html(result, path(cfg.html_out))
    if cfg.md_out:   save_markdown(result, path(cfg.md_out))
    if cfg.csv_out:  save_csv(result, path(cfg.csv_out))
    if cfg.auto_report and not any([cfg.json_out, cfg.html_out, cfg.md_out, cfg.csv_out]):
        auto = f"report_{suffix or datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        save_html(result, auto)


def safe_host(target: str) -> str:
    h = re.sub(r'^https?://', '', target).split("/")[0]
    return re.sub(r'[^\w.-]', '_', h) or "target"


def run_single(args):
    cfg = build_config(args, args.target)
    colors.configure(log_path=cfg.log_out, quiet=args.quiet, no_color=args.no_color)
    banner()
    if not authorize(cfg.normalized_target(), args.yes):
        raw(f"{Colors.RED}[!] 未确认授权，已终止。{Colors.RESET}")
        colors.close(); sys.exit(1)

    target = cfg.normalized_target()
    log("INFO", f"目标: {Colors.CYAN}{Colors.BOLD}{target}{Colors.RESET}")
    log("INFO", f"线程: {cfg.threads} | 超时: {cfg.timeout}s | 代理: {cfg.proxy or '无'} "
                f"| 模式: {'被动' if cfg.passive else '主动'}")
    from core.engine import run_scan, total_checks
    log("INFO", f"作用域: {', '.join(cfg.scope) or cfg.host()} | canary: {cfg.canary}")
    log("INFO", f"内置检测规则/签名: {Colors.BOLD}{total_checks(cfg)}+{Colors.RESET} 条"
                f"（模板 + 敏感路径 + 指纹 + 载荷 + 端口 + 字典）")
    log("INFO", f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    result = run_scan(cfg, verbose=True)

    raw(f"\n{Colors.PURPLE}{'─'*55}{Colors.RESET}")
    print_terminal(result)
    save_reports(cfg, result)
    colors.close()


def run_targets_file(args):
    colors.configure(log_path=args.log, quiet=args.quiet, no_color=args.no_color)
    banner()
    targets = load_targets(args.targets)
    if not targets:
        raw(f"{Colors.RED}[!] 目标文件为空。{Colors.RESET}"); return
    if not authorize(f"{len(targets)} 个目标", args.yes):
        raw(f"{Colors.RED}[!] 未确认授权，已终止。{Colors.RESET}")
        colors.close(); sys.exit(1)

    base = build_config(args, targets[0])
    results = run_batch(base, targets, concurrency=args.concurrency)

    raw(f"\n{Colors.PURPLE}{'═'*65}{Colors.RESET}")
    raw(f"{Colors.BOLD}  批量扫描汇总{Colors.RESET}")
    raw(f"{Colors.PURPLE}{'═'*65}{Colors.RESET}")
    for tgt in targets:
        res = results.get(tgt)
        if not res:
            continue
        s = res.summary()
        raw(f"  {tgt}  →  风险 {res.risk_score()}/100 [{res.risk_grade()}]  "
            f"(C:{s['CRITICAL']} H:{s['HIGH']} M:{s['MEDIUM']} L:{s['LOW']})")
        save_reports(base, res, suffix=safe_host(tgt))
    colors.close()


def main():
    args = parse_args()

    if args.web:
        from webui.app import main as web_main
        web_main(); return

    if args.targets:
        run_targets_file(args); return

    if not args.target:
        raw("用法: python main.py <目标URL>  |  -f targets.txt  |  --web")
        sys.exit(1)

    run_single(args)


if __name__ == "__main__":
    main()
