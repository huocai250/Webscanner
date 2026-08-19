"""
JavaScript 密钥/端点扫描模块（被动）
Author: 火柴 | GitHub: huocai250

抓取页面引用的 .js 文件，在其中检索硬编码密钥/令牌，并提取隐藏的 API 端点。
前端 JS 常泄露 API Key、内部接口路径等，是重要且常被忽视的攻击面。
"""
import re
from urllib.parse import urljoin, urlparse
from core.scanner import BaseScanner
from core.colors import log
from modules.sensitive import PATTERNS   # 复用密钥正则

# JS 中提取 API 端点/路径
ENDPOINT_RE = re.compile(
    r'["\'`](/[a-zA-Z0-9_\-/]{2,}(?:\.(?:json|php|do|action|api))?'
    r'|https?://[a-zA-Z0-9.\-]+/[a-zA-Z0-9_\-/]{2,})["\'`]')

# 额外的高价值密钥线索（补充 sensitive 的 PATTERNS）
EXTRA = {
    "Firebase URL": (r'https://[a-z0-9-]+\.firebaseio\.com', "MEDIUM"),
    "Google OAuth": (r'[0-9]+-[a-z0-9]{32}\.apps\.googleusercontent\.com', "MEDIUM"),
    "Authorization Bearer": (r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}', "HIGH"),
    "Basic Auth": (r'(?i)basic\s+[A-Za-z0-9=]{16,}', "MEDIUM"),
}

MAX_JS = 25


class JSSecretScanner(BaseScanner):
    name = "jssecrets"
    passive = True

    def run(self):
        log("INFO", "JavaScript 密钥/端点扫描...")
        r = self.baseline(self.target)
        if not r:
            return
        js_urls = self._extract_js(r.text or "", r.url)
        if not js_urls:
            log("INFO", "  未发现外部 JS 文件")
            return
        log("INFO", f"  分析 {len(js_urls)} 个 JS 文件...")
        self.map(self._scan_js, js_urls)

    def _extract_js(self, html, base):
        urls = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(base, m.group(1))
            if urlparse(full).netloc == urlparse(self.target).netloc:
                urls.add(full.split("#")[0])
        return list(urls)[:MAX_JS]

    def _scan_js(self, url):
        r = self.get(url)
        if not r or not r.text:
            return None
        body = r.text
        # 1) 密钥检索
        allpat = {**PATTERNS, **EXTRA}
        for name, (pat, sev) in allpat.items():
            if name in ("Email Address", "Internal IP", "Phone (CN)"):
                continue  # JS 里这些噪音大，跳过
            m = re.search(pat, body)
            if m:
                snippet = m.group(0)[:40]
                log("VULN", f"[JS密钥] {name} @ {url}")
                self.add("敏感信息泄露", sev,
                         f"JS 文件中疑似硬编码 {name}",
                         evidence=f"{snippet}… @ {url}", url=url, confidence="疑似")
        # 2) 端点提取（信息级）
        endpoints = set()
        for m in ENDPOINT_RE.finditer(body):
            ep = m.group(1)
            if len(ep) > 4 and not ep.endswith((".js", ".css", ".png", ".jpg",
                                                 ".svg", ".gif", ".woff")):
                endpoints.add(ep)
        if endpoints:
            sample = ", ".join(sorted(endpoints)[:12])
            self.add("信息泄露", "INFO",
                     f"JS 中发现 {len(endpoints)} 个接口/路径线索",
                     evidence=f"{sample} @ {url}", url=url, confidence="信息")
        return url
