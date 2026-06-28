#!/usr/bin/env python3
"""
WebVulnScanner v7.0 — 全功能 Web 漏洞扫描与自动利用框架
Author : 火柴
GitHub : https://github.com/huocai250

[v7.0 新增]
  - Web UI: Flask 实时界面，SSE 进度推送
  - 指纹识别: 100+ 框架/CMS/中间件规则
  - 插件系统: plugins/ 热加载自定义模块
  - 异步引擎: asyncio 并发多目标扫描
  - SSRF 利用: 云元数据 / 内网探测
  - XXE 利用: 数据外带 / 文件读取

用法:
  python main.py https://example.com            # 命令行扫描
  python main.py --webui                        # 启动 Web UI
  python main.py -f targets.txt --exploit       # 批量利用
"""
import sys
import os
import time
import shutil
import logging
from datetime import datetime
from pathlib import Path

# 自动清理旧 __pycache__，防止旧版缓存干扰
_BASE = os.path.dirname(os.path.abspath(__file__))
for _r, _d, _f in os.walk(_BASE):
    if '__pycache__' in _d:
        try:
            shutil.rmtree(os.path.join(_r, '__pycache__'))
        except OSError as e:
            pass  # 删除缓存失败不影响运行，忽略权限错误

sys.path.insert(0, _BASE)

from core.logger        import banner, setup_logger, C
from core.config        import parse_config, ScanConfig
from core.result        import ScanResult
from core.scanner       import validate_url
from core.rate_limiter  import RateLimiter
from core.plugin_manager import PluginManager
from core.async_scanner  import AsyncScanEngine
from utils.http         import parse_cookies, parse_headers, normalize_url
from utils.report       import print_terminal, save_json, save_html, save_csv

# ── 模块导入 ──────────────────────────────────────────────────
from modules.info           import InfoGatherer
from modules.fingerprint    import FingerprintScanner
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


# ── 单目标扫描函数 ────────────────────────────────────────────

def scan_target(target: str, cfg: ScanConfig) -> ScanResult:
    """对单个目标执行完整扫描，返回 ScanResult"""
    try:
        target = validate_url(target)
    except ValueError as e:
        log.error(f"无效目标: {e}")
        return None

    log.info(f"{C.CYAN}{C.BOLD}目标: {target}{C.RESET}")
    result = ScanResult(target)
    rl     = RateLimiter(cfg.rate_limit)
    kw     = dict(
        timeout      = cfg.timeout,
        threads      = cfg.threads,
        cookies      = parse_cookies(cfg.cookie),
        headers      = parse_headers(cfg.headers),
        proxy        = cfg.proxy or None,
        rate_limiter = rl,
        max_retries  = cfg.max_retries,
        user_agent   = cfg.user_agent or None,
        exploit_mode = cfg.exploit,
    )

    fast  = cfg.fast_mode
    only  = set(cfg.modules) if cfg.modules else None
    exploit_types = set(cfg.exploit_types) if cfg.exploit_types else \
                    {"sqli", "cmdi", "xss", "lfi", "ssrf"}

    def mk(cls, **extra):
        m = cls(target, result, **{**kw, **extra})
        if cfg.reverse_host:
            m.reverse_host = cfg.reverse_host
            m.reverse_port = cfg.reverse_port
        return m

    # ── 扫描计划 ─────────────────────────────────────────────
    plan = [
        # key,            label,                         module实例,                          skip?
        ("crawler",      "爬虫 & 参数发现",              mk(Crawler, max_pages=30),           False),
        ("info",         "信息收集 & WAF",               mk(InfoGatherer),                    False),
        ("fingerprint",  "指纹识别（100+规则）",          mk(FingerprintScanner),              False),
        ("cms",          "CMS 专项扫描",                 mk(CMSScanner),                      False),
        ("headers",      "HTTP 安全头",                  mk(HeaderChecker),                   False),
        ("ssl",          "SSL/TLS",                      mk(SSLChecker),                      False),
        ("sensitive",    "敏感信息泄露",                  mk(SensitiveInfoScanner),            False),
        ("cors",         "CORS 配置",                    mk(CORSScanner),                     False),
        ("csrf",         "CSRF",                         mk(CSRFScanner),                     False),
        ("clickjacking", "Clickjacking & 配置",          mk(ClickjackingScanner),             False),
        ("methods",      "危险 HTTP 方法",               mk(HTTPMethodScanner),               False),
        ("redirect",     "开放重定向",                   mk(OpenRedirectScanner),             False),
        ("jwt",          "JWT 安全",                     mk(JWTScanner),                      False),
        ("injections",   "Log4Shell / CRLF / Host Header",mk(InjectionScanner),              False),
        ("api",          "API 安全 & GraphQL",           mk(APIScanner),                      False),
        ("sqli",         _label("SQL 注入", cfg, "sqli"),mk(SQLiScanner),                     cfg.skip_sqli),
        ("xss",          _label("XSS & SSTI", cfg,"xss"),mk(XSSScanner),                     cfg.skip_xss),
        ("lfi",          _label("LFI & 命令注入",cfg,"lfi"),mk(LFIScanner),                  cfg.skip_lfi),
        ("traversal",    "路径穿越",                     mk(PathTraversalScanner),            fast),
        ("xxe",          "XXE 注入",                     mk(XXEScanner),                      fast),
        ("ssrf",         _label("SSRF", cfg, "ssrf"),   mk(SSRFScanner),                     fast),
        ("upload",       "文件上传漏洞",                  mk(FileUploadScanner),               cfg.skip_upload or fast),
        ("creds",        "弱口令 & 默认凭据",             mk(WeakCredScanner),                 cfg.skip_bruteforce or fast),
        ("subdomain",    "子域名枚举",                   mk(SubdomainScanner),                cfg.skip_subdomain or fast),
        ("ports",        "端口扫描",                     mk(PortScanner),                     cfg.skip_ports or fast),
        ("dirbust",      "目录枚举",                     mk(DirBuster, wordlist_file=cfg.wordlist or None),
                                                                                             cfg.skip_dirbust or fast),
    ]

    # ── 加载插件模块 ──────────────────────────────────────────
    plugin_mgr = PluginManager()
    plugins    = plugin_mgr.discover()
    for p in plugins:
        key   = p["meta"]["key"]
        label = p["meta"]["name"]
        try:
            mod = p["cls"](target, result, **kw)
            plan.append((key, f"[插件] {label}", mod, False))
            log.info(f"插件已加入扫描计划: {label}")
        except Exception as e:
            log.warning(f"插件 [{label}] 初始化失败: {e}")

    # ── 执行 ─────────────────────────────────────────────────
    active = [(k,l,m,s) for k,l,m,s in plan
              if not s and (only is None or k in only)]
    total  = len(active)

    for idx, (key, label, module, _) in enumerate(active, 1):
        print(f"\n{C.PURPLE}{'─'*62}{C.RESET}")
        log.info(f"[{idx}/{total}] ▶ {C.BOLD}{label}{C.RESET}")
        try:
            module.run()
        except KeyboardInterrupt:
            log.warning("用户中断，正在生成报告...")
            break
        except Exception as e:
            log.error(f"模块 [{label}] 异常: {type(e).__name__}: {e}")
            log.debug("", exc_info=True)

    return result


def _label(base: str, cfg: ScanConfig, etype: str) -> str:
    """为带利用功能的模块生成标签"""
    types = set(cfg.exploit_types) if cfg.exploit_types else \
            {"sqli","cmdi","xss","lfi","ssrf"}
    if cfg.exploit and etype in types:
        return f"{base} + 自动利用"
    return base


# ── 报告保存 ──────────────────────────────────────────────────

def save_reports(result: ScanResult, cfg: ScanConfig, slug: str = ""):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    s  = slug or ts

    if cfg.output_json:
        save_json(result, cfg.output_json)
    if cfg.output_html:
        save_html(result, cfg.output_html)
    else:
        auto = f"report_{s}.html"
        save_html(result, auto)
        log.info(f"HTML 报告: {auto}")
    if cfg.output_csv:
        save_csv(result, cfg.output_csv)


# ── 目标加载 ──────────────────────────────────────────────────

def load_targets(cfg: ScanConfig):
    targets = []
    if cfg.target:
        targets.append(normalize_url(cfg.target))
    if cfg.target_file:
        p = Path(cfg.target_file)
        if not p.exists():
            log.error(f"目标文件不存在: {cfg.target_file}")
        else:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(normalize_url(line))
            log.info(f"从文件加载 {len(targets)} 个目标")
    # 去重保序
    seen = set()
    return [t for t in targets if not (t in seen or seen.add(t))]


# ── 主函数 ────────────────────────────────────────────────────

def main():
    banner()

    # 检测是否启动 Web UI
    if "--webui" in sys.argv:
        _start_webui()
        return

    cfg = parse_config()

    # 初始化日志
    global log
    log = setup_logger(
        name     = "webscan",
        level    = "WARNING" if cfg.quiet else cfg.log_level,
        log_file = cfg.log_file or None,
    )
    log = logging.getLogger("webscan")

    targets = load_targets(cfg)
    if not targets:
        print(f"{C.RED}错误: 未指定目标\n"
              f"  命令行扫描: python main.py https://example.com\n"
              f"  Web UI:     python main.py --webui{C.RESET}")
        sys.exit(1)

    # 警告横幅
    print(f"\n{C.YELLOW}{'─'*62}")
    print(f"  ⚠  本工具仅供已获书面授权的渗透测试使用")
    print(f"     未授权扫描违反《网络安全法》及相关法律！")
    if cfg.exploit:
        print(f"  ⚡ 漏洞自动利用已开启")
        etypes = ', '.join(cfg.exploit_types) if cfg.exploit_types else '全部'
        print(f"     利用类型: {etypes}")
    if cfg.reverse_host:
        print(f"  🐚 反弹Shell: {cfg.reverse_host}:{cfg.reverse_port}")
    print(f"{'─'*62}{C.RESET}\n")
    time.sleep(1)

    log.info(f"线程:{cfg.threads} | 超时:{cfg.timeout}s | "
             f"速率:{cfg.rate_limit}s | 重试:{cfg.max_retries}")
    log.info(f"代理:{cfg.proxy or '无'} | 快速:{cfg.fast_mode} | "
             f"目标数:{len(targets)}")

    # ── 单目标 vs 多目标 ─────────────────────────────────────
    if len(targets) == 1:
        result = scan_target(targets[0], cfg)
        if result:
            print(f"\n{C.PURPLE}{'═'*62}{C.RESET}")
            print_terminal(result)
            from urllib.parse import urlparse
            slug = urlparse(targets[0]).netloc.replace(":", "_").replace(".", "_")
            save_reports(result, cfg, slug)
            _print_summary(targets[0], result)
    else:
        # 多目标异步并发扫描
        log.info(f"[异步引擎] 启动，{len(targets)} 个目标，"
                 f"最大并发: {min(cfg.threads, len(targets), 5)}")

        def _scan_fn(t):
            return scan_target(t, cfg)

        def _progress(target, done, total, result):
            counts = result.summary() if result else {}
            c = counts.get("CRITICAL",0) + counts.get("HIGH",0)
            log.info(f"[{done}/{total}] 完成: {target}"
                     + (f" — {c} 个高危" if c else ""))

        engine  = AsyncScanEngine(
            max_concurrent=min(cfg.threads, len(targets), 5),
            progress_cb=_progress,
        )
        results = engine.run_sync(targets, _scan_fn)

        # 汇总报告
        total_f = sum(r.total() for r in results.values() if r)
        print(f"\n{C.BOLD}{'═'*62}")
        print(f"批量扫描完成！{len(results)} 个目标，共发现 {total_f} 个问题{C.RESET}")

        for target, result in results.items():
            if not result:
                continue
            print(f"\n{C.CYAN}── {target} ──{C.RESET}")
            print_terminal(result)
            from urllib.parse import urlparse
            slug = urlparse(target).netloc.replace(":", "_").replace(".", "_")
            save_reports(result, cfg, slug)
            _print_summary(target, result)


def _print_summary(target: str, result: ScanResult):
    counts = result.summary()
    print(f"\n{C.BOLD}[{target}] "
          f"{C.RED}C:{counts['CRITICAL']} H:{counts['HIGH']}{C.RESET} "
          f"{C.YELLOW}M:{counts['MEDIUM']}{C.RESET} "
          f"{C.BLUE}L:{counts['LOW']}{C.RESET} "
          f"I:{counts['INFO']} | 耗时:{result.elapsed()}{C.RESET}")


def _start_webui():
    """启动 Flask Web UI"""
    try:
        from web.app import create_app
        app = create_app()
        host = os.environ.get("WEBSCAN_HOST", "0.0.0.0")
        port = int(os.environ.get("WEBSCAN_PORT", "5000"))
        print(f"\n{C.GREEN}{'─'*50}")
        print(f"  🌐 WebVulnScanner v7.0 Web UI 启动中")
        print(f"  访问地址: http://127.0.0.1:{port}")
        print(f"  按 Ctrl+C 停止")
        print(f"{'─'*50}{C.RESET}\n")
        app.run(host=host, port=port, debug=False, threaded=True)
    except ImportError:
        print(f"{C.RED}Flask 未安装，请运行: pip install flask{C.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
