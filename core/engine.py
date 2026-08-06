"""
扫描引擎：单目标扫描主循环（被 CLI / 批量 / Web UI 共用）
Author: 火柴 | GitHub: huocai250
"""
from core.config import ScanConfig
from core.result import ScanResult
from core.scanner import ScanContext
from core.colors import log, raw, Colors
from core.plugins import load_plugins

from modules import (
    Crawler, InfoGatherer, Fingerprinter, HeaderChecker, SSLChecker,
    SensitiveInfoScanner, MisconfigScanner, MethodScanner, GraphQLScanner,
    HostHeaderScanner, JWTScanner, CMSScanner, CORSScanner, CSRFScanner,
    OpenRedirectScanner, CRLFScanner, SQLiScanner, XSSScanner, LFIScanner,
    PathTraversalScanner, XXEScanner, SSRFScanner, Log4ShellScanner,
    SubdomainScanner, PortScanner, DirBuster,
)

# 扫描执行顺序（爬虫/指纹先行，主动注入模块在后）
PLAN = [
    Crawler, InfoGatherer, Fingerprinter, HeaderChecker, SSLChecker,
    SensitiveInfoScanner, MisconfigScanner, MethodScanner, GraphQLScanner,
    HostHeaderScanner, JWTScanner, CMSScanner, CORSScanner, CSRFScanner,
    OpenRedirectScanner, CRLFScanner, SQLiScanner, XSSScanner, LFIScanner,
    PathTraversalScanner, XXEScanner, SSRFScanner, Log4ShellScanner,
    SubdomainScanner, PortScanner, DirBuster,
]

DISPLAY = {
    "crawler": "爬虫", "info": "信息收集", "fingerprint": "指纹识别",
    "headers": "安全头检测", "ssl": "SSL/TLS", "sensitive": "敏感信息",
    "misconfig": "配置错误", "methods": "HTTP 方法", "graphql": "GraphQL",
    "hostheader": "Host 头注入", "jwt": "JWT 安全", "cms": "CMS 专项",
    "cors": "CORS", "csrf": "CSRF", "redirect": "开放重定向", "crlf": "CRLF 注入",
    "sqli": "SQL 注入", "xss": "XSS", "lfi": "LFI/命令注入",
    "traversal": "路径穿越", "xxe": "XXE 注入", "ssrf": "SSRF",
    "log4shell": "Log4Shell", "subdomain": "子域名枚举",
    "ports": "端口扫描", "dirbust": "目录枚举",
}


def display_name(name: str) -> str:
    return DISPLAY.get(name, name)


def build_plan(cfg: ScanConfig):
    """返回本次扫描应运行的模块类列表（含插件、应用 skip/passive）。"""
    plan = list(PLAN)
    if cfg.plugins_dir:
        plan += load_plugins(cfg.plugins_dir)

    selected = []
    for cls in plan:
        name = getattr(cls, "name", cls.__name__)
        if name in cfg.skip:
            continue
        if cfg.passive and not getattr(cls, "passive", False):
            continue
        selected.append(cls)
    return selected


def run_scan(cfg: ScanConfig, progress=None, verbose=True) -> ScanResult:
    """
    对单个目标执行完整扫描并返回结果。
    progress: 可选回调 progress(name_cn, done, total, findings_so_far)
    """
    result = ScanResult(cfg.normalized_target())
    ctx = ScanContext(cfg, result)
    plan = build_plan(cfg)
    total = len(plan)

    for i, cls in enumerate(plan, 1):
        name = getattr(cls, "name", cls.__name__)
        cn = display_name(name)
        if verbose:
            raw(f"\n{Colors.PURPLE}{'─'*55}{Colors.RESET}")
            log("INFO", f"▶ 模块 [{i}/{total}]: {Colors.BOLD}{cn}{Colors.RESET}")
        try:
            cls(ctx).run()
        except KeyboardInterrupt:
            log("WARN", "用户中断，生成当前报告...")
            break
        except Exception as e:
            log("WARN", f"模块 [{cn}] 异常: {e}")
        if progress:
            try:
                progress(cn, i, total, len(result.findings))
            except Exception:
                pass

    result.finish()
    return result
