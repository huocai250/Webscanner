"""
HTTP 安全头检测模块
Author: 火柴 | GitHub: huocai250
v4.0: 使用基线缓存
"""
from core.scanner import BaseScanner
from core.colors import log


class HeaderChecker(BaseScanner):
    name = "headers"
    passive = True

    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("HIGH",   "缺少 HSTS，存在协议降级风险"),
        "Content-Security-Policy":   ("HIGH",   "缺少 CSP，存在 XSS 防护缺失风险"),
        "X-Frame-Options":           ("MEDIUM", "缺少 X-Frame-Options，存在 Clickjacking 风险"),
        "X-Content-Type-Options":    ("LOW",    "缺少 X-Content-Type-Options"),
        "Referrer-Policy":           ("LOW",    "缺少 Referrer-Policy，可能泄露请求来源"),
        "Permissions-Policy":        ("LOW",    "缺少 Permissions-Policy"),
        "X-XSS-Protection":          ("LOW",    "缺少 X-XSS-Protection"),
        "Cross-Origin-Opener-Policy":("LOW",    "缺少 COOP 头"),
        "Cross-Origin-Resource-Policy": ("LOW", "缺少 CORP 头"),
    }

    LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                    "X-Generator", "X-Runtime", "X-Debug-Token"]

    def run(self):
        log("INFO", "检测 HTTP 安全头...")
        r = self.baseline()
        if not r:
            log("WARN", "无法获取响应头")
            return
        self._check_missing(r)
        self._check_leak(r)
        self._check_cookie(r)

    def _check_missing(self, r):
        for header, (severity, desc) in self.SECURITY_HEADERS.items():
            if header not in r.headers:
                log("WARN", f"缺少安全头: {header}")
                self.add("安全头缺失", severity, desc, url=self.target)
            else:
                log("OK", f"{header}: {r.headers[header][:80]}")

    def _check_leak(self, r):
        for h in self.LEAK_HEADERS:
            if h in r.headers:
                log("WARN", f"信息泄露头: {h} = {r.headers[h]}")
                self.add("信息泄露", "LOW",
                         f"响应头暴露版本信息: {h}={r.headers[h]}", url=self.target)

    def _check_cookie(self, r):
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("缺少 Secure 标志")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("缺少 HttpOnly 标志")
            if not cookie.get_nonstandard_attr("SameSite"):
                issues.append("缺少 SameSite 属性")
            if issues:
                log("WARN", f"Cookie [{cookie.name}] 安全问题: {', '.join(issues)}")
                self.add("Cookie 安全", "MEDIUM",
                         f"Cookie '{cookie.name}' 安全配置不当: {', '.join(issues)}",
                         url=self.target)
