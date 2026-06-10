#!/usr/bin/env python3
"""
WebVulnScanner v6.0 — 全功能 Web 漏洞扫描与自动利用框架
Author : 火柴
GitHub : https://github.com/huocai250
警告   : 仅供已获授权的渗透测试使用，未经授权扫描属于违法行为！

[v6.0 新增]
  - 爬虫模块：自动发现参数和表单
  - CMS专项扫描：WordPress/Joomla/ThinkPHP/Shiro/Actuator
  - 漏洞自动利用：SQLi(数据库dump)/命令注入(系统信息+反弹shell)/XSS(PoC+Cookie窃取)/LFI(文件读取)
  - 速率限制：防封IP
  - 批量扫描：支持目标文件
  - CSV报告：兼容Excel
  - 配置文件：scanner.cfg
  - 统一 logging 模块
"""
import sys
import os
import time
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 清理旧 .pyc 缓存，防止版本混用导致问题
import shutil
_base = os.path.dirname(os.path.abspath(__file__))
for _root, _dirs, _files in os.walk(_base):
    if '__pycache__' in _dirs:
        try:
            shutil.rmtree(os.path.join(_root, '__pycache__'))
        except OSError:
            pass

from core.logger     import banner, setup_logger, C
from core.config     import parse_config, ScanConfig
from core.result     import ScanResult
from core.scanner    import validate_url
from core.rate_limiter import RateLimiter
from utils.http      import parse_cookies, parse_headers, normalize_url
from utils.report    import print_terminal, save_json, save_html, save_csv

# ── 模块导入 ──────────────────────────────────────────────────
from modules.info           import InfoGatherer
from modules.headers        import HeaderChecker
from modules.ssl_check      import SSLChecker
from modules.sensitive      import SensitiveInfoScanner
from modules.cors           import CORSScanner
from modules.csrf           import CSRFScanner
from modules.clickjacking   import ClickjackingScanner
from modules.http_methods   import HTTPMethodScanner
from modules.redirect       import OpenRedirectScanner
from modules.jwt_check      import JWTScanner
from modules.injections     import InjectionScanner
from modules.api_security   import APIScanner
from modules.sqli           import SQLiScanner
from modules.xss            import XSSScanner
from modules.lfi            import LFIScanner
from modules.path_traversal import PathTraversalScanner
from modules.xxe            import XXEScanner
from modules.ssrf           import SSRFScanner
from modules.file_upload    import FileUploadScanner
from modules.weak_creds     import WeakCredScanner
from modules.subdomain      import SubdomainScanner
from modules.ports          import PortScanner
from modules.dirbust        import DirBuster
from modules.cms_scan       import CMSScanner
from modules.crawler        import Crawler

log = logging.getLogger("webscan")


# ── 单目标扫描 ────────────────────────────────────────────────

def scan_target(target: str, cfg: ScanConfig) -> ScanResult:
    """对单个目标执行完整扫描"""

    try:
        target = validate_url(target)
    except ValueError as e:
        log.error(f"无效目标: {e}")
        return None

    log.info(f"{C.CYAN}{C.BOLD}目标: {target}{C.RESET}")
    result  = ScanResult(target)
    rl      = RateLimiter(cfg.rate_limit)
    cookies = parse_cookies(cfg.cookie)
    headers = parse_headers(cfg.headers)

    # [新增] 通用模块参数
    common_kw = dict(
        timeout      = cfg.timeout,
        threads      = cfg.threads,
        cookies      = cookies,
        headers      = headers,
        proxy        = cfg.proxy or None,
        rate_limiter = rl,
        max_retries  = cfg.max_retries,
        user_agent   = cfg.user_agent or None,
        exploit_mode = cfg.exploit,
    )

    fast = cfg.fast_mode
    only = set(cfg.modules) if cfg.modules else None

    def mk(cls, **extra):
        """模块工厂"""
        kw = {**common_kw, **extra}
        m  = cls(target, result, **kw)
        # 注入反弹 Shell 配置
        if cfg.reverse_host:
            m.reverse_host = cfg.reverse_host
            m.reverse_port = cfg.reverse_port
        return m

    # 利用类型过滤
    exploit_types = set(cfg.exploit_types) if cfg.exploit_types else \
                    {"sqli","cmdi","xss","lfi","ssrf"}

    # ── 扫描计划 ─────────────────────────────────────────────
    # (key, 显示名称, 模块实例, 是否跳过)
    plan = [
        # 信息收集类（始终运行）
        ("crawler",      "爬虫 & 参数发现",
         mk(Crawler, max_pages=30),             False),
        ("info",         "信息收集 & WAF 识别",
         mk(InfoGatherer),                       False),
        ("cms",          "CMS 专项扫描",
         mk(CMSScanner),                         False),
        ("headers",      "HTTP 安全头",
         mk(HeaderChecker),                      False),
        ("ssl",          "SSL/TLS",
         mk(SSLChecker),                         False),
        ("sensitive",    "敏感信息泄露",
         mk(SensitiveInfoScanner),               False),
        ("cors",         "CORS 配置",
         mk(CORSScanner),                        False),
        ("csrf",         "CSRF",
         mk(CSRFScanner),                        False),
        ("clickjacking", "Clickjacking & 配置",
         mk(ClickjackingScanner),                False),
        ("methods",      "危险 HTTP 方法",
         mk(HTTPMethodScanner),                  False),
        ("redirect",     "开放重定向",
         mk(OpenRedirectScanner),                False),
        ("jwt",          "JWT 安全",
         mk(JWTScanner),                         False),
        ("injections",   "Log4Shell/CRLF/Host Header",
         mk(InjectionScanner),                   False),
        ("api",          "API 安全 & GraphQL",
         mk(APIScanner),                         False),
        # 漏洞检测类
        ("sqli",         "SQL 注入" + (" + 自动利用" if cfg.exploit and "sqli" in exploit_types else ""),
         mk(SQLiScanner),                        cfg.skip_sqli),
        ("xss",          "XSS & SSTI" + (" + 自动利用" if cfg.exploit and "xss" in exploit_types else ""),
         mk(XSSScanner),                         cfg.skip_xss),
        ("lfi",          "LFI & 命令注入" + (" + 自动利用" if cfg.exploit and ("lfi" in exploit_types or "cmdi" in exploit_types) else ""),
         mk(LFIScanner),                         cfg.skip_lfi),
        ("traversal",    "路径穿越",
         mk(PathTraversalScanner),               fast),
        ("xxe",          "XXE 注入",
         mk(XXEScanner),                         fast),
        ("ssrf",         "SSRF",
         mk(SSRFScanner),                        fast),
        ("upload",       "文件上传漏洞",
         mk(FileUploadScanner),                  cfg.skip_upload or fast),
        ("creds",        "弱口令 & 默认凭据",
         mk(WeakCredScanner),                    cfg.skip_bruteforce or fast),
        ("subdomain",    "子域名枚举",
         mk(SubdomainScanner),                   cfg.skip_subdomain or fast),
        ("ports",        "端口扫描",
         mk(PortScanner),                        cfg.skip_ports or fast),
        ("dirbust",      "目录枚举",
         mk(DirBuster, wordlist_file=cfg.wordlist or None),
         cfg.skip_dirbust or fast),
    ]

    # ── 执行扫描 ─────────────────────────────────────────────
    total_modules = sum(1 for k,_,_,skip in plan
                        if not skip and (only is None or k in only))
    done = 0

    for key, label, module, skip in plan:
        if only and key not in only:
            continue
        if skip:
            log.info(f"[SKIP] {label}")
            continue

        done += 1
        print(f"\n{C.PURPLE}{'─'*60}{C.RESET}")
        log.info(f"[{done}/{total_modules}] ▶ {C.BOLD}{label}{C.RESET}")

        try:
            module.run()
        except KeyboardInterrupt:
            log.warning("用户中断，生成当前报告...")
            break
        except Exception as e:
            log.error(f"模块 [{label}] 异常: {type(e).__name__}: {e}")
            log.debug("", exc_info=True)

    return result


# ── 报告保存 ──────────────────────────────────────────────────

def save_reports(result: ScanResult, cfg: ScanConfig, target_slug: str = ""):
    """保存所有格式报告"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = target_slug or ts

    if cfg.output_json:
        save_json(result, cfg.output_json)
    if cfg.output_html:
        save_html(result, cfg.output_html)
    else:
        # 默认自动生成 HTML
        auto_html = f"report_{slug}.html"
        save_html(result, auto_html)
        log.info(f"HTML 报告: {auto_html}")

    if cfg.output_csv:
        save_csv(result, cfg.output_csv)


# ── 加载批量目标 ──────────────────────────────────────────────

def load_targets(cfg: ScanConfig):
    """[新增] 从文件或参数加载目标列表"""
    targets = []
    if cfg.target:
        targets.append(cfg.target)
    if cfg.target_file:
        path = Path(cfg.target_file)
        if not path.exists():
            log.error(f"目标文件不存在: {cfg.target_file}")
        else:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(normalize_url(line))
            log.info(f"从文件加载 {len(targets)} 个目标")
    return targets


# ── 主函数 ────────────────────────────────────────────────────

def main():
    banner()

    cfg = parse_config()

    # 初始化日志
    global log
    log = setup_logger(
        name     = "webscan",
        level    = "WARNING" if cfg.quiet else cfg.log_level,
        log_file = cfg.log_file or None,
    )
    log = logging.getLogger("webscan")

    # 加载目标
    targets = load_targets(cfg)
    if not targets:
        print(f"{C.RED}错误: 未指定目标，使用 -h 查看帮助{C.RESET}")
        sys.exit(1)

    # 警告
    print(f"\n{C.YELLOW}{'─'*60}")
    print(f"  ⚠  本工具仅供已获书面授权的渗透测试使用")
    print(f"     未授权扫描违反《网络安全法》及相关法律！")
    if cfg.exploit:
        print(f"  ⚡ 漏洞自动利用已开启")
        if cfg.exploit_types:
            print(f"     利用类型: {', '.join(cfg.exploit_types)}")
        else:
            print(f"     利用类型: 全部 (sqli/cmdi/xss/lfi)")
    if cfg.reverse_host:
        print(f"  🐚 反弹Shell监听: {cfg.reverse_host}:{cfg.reverse_port}")
    print(f"{'─'*60}{C.RESET}\n")
    time.sleep(1)

    # 扫描参数摘要
    log.info(f"线程: {cfg.threads} | 超时: {cfg.timeout}s | "
             f"速率限制: {cfg.rate_limit}s | 重试: {cfg.max_retries}次")
    log.info(f"代理: {cfg.proxy or '无'} | "
             f"快速模式: {'是' if cfg.fast_mode else '否'}")

    # ── 批量扫描 ─────────────────────────────────────────────
    all_results = []
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{C.CYAN}{C.BOLD}{'='*60}{C.RESET}")
            print(f"{C.CYAN}[{i}/{len(targets)}] 扫描目标: {target}{C.RESET}")
            print(f"{C.CYAN}{'='*60}{C.RESET}")

        result = scan_target(target, cfg)
        if result is None:
            continue

        all_results.append(result)

        # 输出当前目标报告
        print(f"\n{C.PURPLE}{'═'*60}{C.RESET}")
        print_terminal(result)

        # 生成目标独立报告
        from urllib.parse import urlparse
        slug = urlparse(target).netloc.replace(":", "_").replace(".", "_")
        save_reports(result, cfg, slug)

        counts = result.summary()
        print(f"\n{C.BOLD}[{target}] 完成 | "
              f"{C.RED}CRITICAL:{counts['CRITICAL']} "
              f"HIGH:{counts['HIGH']}{C.RESET} "
              f"{C.YELLOW}MEDIUM:{counts['MEDIUM']}{C.RESET} "
              f"{C.BLUE}LOW:{counts['LOW']}{C.RESET} "
              f"INFO:{counts['INFO']} | "
              f"耗时:{result.elapsed()}{C.RESET}")

    # 多目标汇总
    if len(all_results) > 1:
        total_findings = sum(r.total() for r in all_results)
        print(f"\n{C.BOLD}{'='*60}")
        print(f"批量扫描完成！共 {len(all_results)} 个目标，"
              f"发现 {total_findings} 个问题{C.RESET}")


if __name__ == "__main__":
    main()
