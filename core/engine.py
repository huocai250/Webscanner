"""
扫描引擎：单目标扫描主循环（被 CLI / 批量 / Web UI 共用）
Author: 火柴 | GitHub: huocai250
"""
import os
from core.config import ScanConfig
from core.result import ScanResult
from core.scanner import ScanContext
from core.colors import log, raw, Colors
from core.plugins import load_plugins

from modules import (
    Crawler, InfoGatherer, Fingerprinter, CVEVersionScanner, HeaderChecker,
    SSLChecker, SensitiveInfoScanner, JSSecretScanner, ExposureScanner,
    TemplateScanner, MisconfigScanner, FrontendScanner, WellKnownScanner,
    TakeoverScanner, APIDocsScanner, MethodScanner, GraphQLScanner,
    HostHeaderScanner, JWTScanner, CMSScanner, CORSScanner, CSRFScanner,
    OpenRedirectScanner, CRLFScanner, CachePoisonScanner, SQLiScanner,
    XSSScanner, LFIScanner, PathTraversalScanner, XXEScanner, SSRFScanner,
    Log4ShellScanner, SubdomainScanner, PortScanner, DirBuster,
)

# 扫描执行顺序（爬虫/指纹先行；被动检测居中；主动注入模块在后）
PLAN = [
    Crawler, InfoGatherer, Fingerprinter, CVEVersionScanner,
    HeaderChecker, SSLChecker, SensitiveInfoScanner, JSSecretScanner,
    MisconfigScanner, FrontendScanner, WellKnownScanner, TakeoverScanner,
    APIDocsScanner, TemplateScanner, MethodScanner, GraphQLScanner,
    HostHeaderScanner, JWTScanner, CMSScanner, CORSScanner, CSRFScanner,
    OpenRedirectScanner, CRLFScanner, CachePoisonScanner, SQLiScanner,
    XSSScanner, LFIScanner, PathTraversalScanner, XXEScanner, SSRFScanner,
    Log4ShellScanner, ExposureScanner, SubdomainScanner, PortScanner, DirBuster,
]

DISPLAY = {
    "crawler": "爬虫", "info": "信息收集", "fingerprint": "指纹识别",
    "cveversion": "版本漏洞提示", "headers": "安全头检测", "ssl": "SSL/TLS",
    "sensitive": "敏感信息", "jssecrets": "JS密钥/端点", "misconfig": "配置错误",
    "frontend": "前端安全", "wellknown": "robots/well-known", "takeover": "子域名接管",
    "apidocs": "API文档发现", "templates": "模板签名库", "methods": "HTTP方法",
    "graphql": "GraphQL", "hostheader": "Host头注入", "jwt": "JWT安全",
    "cms": "CMS专项", "cors": "CORS", "csrf": "CSRF", "redirect": "开放重定向",
    "crlf": "CRLF注入", "cachepoison": "缓存投毒", "sqli": "SQL注入", "xss": "XSS",
    "lfi": "LFI/命令注入", "traversal": "路径穿越", "xxe": "XXE注入", "ssrf": "SSRF",
    "log4shell": "Log4Shell", "exposure": "敏感路径暴露", "subdomain": "子域名枚举",
    "ports": "端口扫描", "dirbust": "目录枚举",
}


def display_name(name):
    return DISPLAY.get(name, name)


def total_checks(cfg=None) -> int:
    """统计内置检测规则/签名总量，用于向用户如实展示覆盖面。"""
    n = 0
    try:
        from core.data.exposures import EXPOSURES
        n += len(EXPOSURES)
    except Exception:
        pass
    try:
        from core.template_engine import load_templates, count_checks
        dirs = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "templates")]
        if cfg and getattr(cfg, "templates_dir", None):
            dirs.append(cfg.templates_dir)
        n += count_checks(load_templates(dirs))
    except Exception:
        pass
    # 其余模块内置的规则/字典/载荷
    try:
        from modules.dirbust import BUILTIN_WORDLIST
        n += len(BUILTIN_WORDLIST)
    except Exception:
        pass
    try:
        from modules.ports import PORTS
        n += len(PORTS)
    except Exception:
        pass
    try:
        from modules.fingerprint import FINGERPRINTS
        n += len(FINGERPRINTS)
    except Exception:
        pass
    try:
        from modules.sensitive import PATTERNS, EXPOSED_FILES
        n += len(PATTERNS) + len(EXPOSED_FILES)
    except Exception:
        pass
    try:
        from modules.subdomain import DEFAULT_SUBS
        n += len(DEFAULT_SUBS)
    except Exception:
        pass
    try:
        from modules.apidocs import API_ENDPOINTS
        n += len(API_ENDPOINTS)
    except Exception:
        pass
    # 各注入模块的载荷集合（粗略计入）
    try:
        from modules import sqli, xss, lfi, redirect, traversal, crlf, log4shell
        for mod, attrs in [
            (sqli, ["ERROR_PAYLOADS", "BOOLEAN_PAYLOADS", "TIME_PAYLOADS", "ERROR_PATTERNS"]),
            (xss, ["REFLECTED_PAYLOADS", "SSTI_PAYLOADS", "DOM_INDICATORS"]),
            (lfi, ["LFI_PAYLOADS", "CMD_PAYLOADS", "LFI_SIGNATURES", "CMD_SIGNATURES"]),
            (redirect, ["REDIRECT_PAYLOADS", "REDIRECT_PARAMS"]),
            (traversal, ["TRAVERSALS"]), (crlf, ["PAYLOADS"]),
            (log4shell, ["HEADERS", "PARAMS"]),
        ]:
            for a in attrs:
                v = getattr(mod, a, None)
                if v:
                    n += len(v)
    except Exception:
        pass
    return n


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
