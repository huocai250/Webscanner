"""
全站敏感数据(PII/密钥)深度扫描模块（被动）
Author: 火柴 | GitHub: huocai250

sensitive/jssecrets 主要看首页与 JS；本模块把密钥/PII 正则应用到**爬虫抓取到的
所有页面**响应上，覆盖更全。仅检测与报告，不外泄具体内容（证据做截断/脱敏）。
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from modules.sensitive import PATTERNS

# 高价值且低误报的子集（全站扫描时避免 Email/IP 等高噪声项刷屏）
SCAN_KEYS = ["AWS Access Key", "AWS Secret Key", "Private Key", "Google API Key",
             "Stripe Key", "GitHub Token", "Slack Token", "JWT Token",
             "Database URL", "Chinese ID Card", "Credit Card", "Password in Source"]

MAX_PAGES = 40


class PIIScanner(BaseScanner):
    name = "pii"
    passive = True

    def run(self):
        log("INFO", "全站敏感数据(PII/密钥)深度扫描...")
        urls = self._pages()
        if not urls:
            return
        log("INFO", f"  扫描 {len(urls)} 个页面...")
        reported = set()
        results = self.map(lambda u: self._scan(u, reported), urls)
        hits = sum(len(r) for r in results if r)
        if not hits:
            log("INFO", "  未发现新的敏感数据")

    def _pages(self):
        urls = {self.target}
        for ip in self.ctx.injection_points:
            urls.add(ip["url"])
        return list(urls)[:MAX_PAGES]

    def _scan(self, url, reported):
        r = self.probe_get(url)
        if not r or not r.text:
            return []
        body = r.text
        found = []
        for name in SCAN_KEYS:
            pat, sev = PATTERNS[name]
            m = re.search(pat, body)
            if not m:
                continue
            # 去重：同类命中只报一次（避免全站刷屏）
            dedup_key = (name, m.group(0)[:12])
            if dedup_key in reported:
                continue
            reported.add(dedup_key)
            snippet = self._mask(m.group(0))
            log("VULN", f"[PII/密钥] {name} @ {url}")
            self.add("敏感信息泄露", sev,
                     f"页面响应中发现疑似 {name}",
                     evidence=f"{snippet} @ {url}", url=url, confidence="疑似")
            found.append(name)
        return found

    @staticmethod
    def _mask(s):
        s = s[:40]
        if len(s) > 12:
            return s[:6] + "…" + s[-4:]   # 证据脱敏
        return s
