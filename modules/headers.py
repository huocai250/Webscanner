"""
HTTP 安全头检测模块
Author: 火柴 | GitHub: huocai250

修复:
- Cookie HttpOnly 检测：用 _rest dict 替代不可靠的 has_nonstandard_attr
- 更准确的 SameSite 属性检测
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


from core.scanner import BaseScanner


class HeaderChecker(BaseScanner):
    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("HIGH",   "缺少 HSTS，存在协议降级攻击风险"),
        "Content-Security-Policy":   ("HIGH",   "缺少 CSP，XSS 防护缺失"),
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
        _before = self.result.total()
        log.info( "检测 HTTP 安全头...")
        r = self.get(self.target)
        if not r:
            log.warning( "无法获取响应，跳过安全头检测")
            return
        self._check_missing(r)
        self._check_leak(r)
        self._check_csp_quality(r)
        self._check_cookies(r)
        self._log_module_done("HTTP安全头", _before)

    def _check_missing(self, r):
        for header, (severity, desc) in self.SECURITY_HEADERS.items():
            if header not in r.headers:
                log.warning( f"缺少: {header}")
                self.result.add("安全头缺失", severity, desc, url=self.target)
            else:
                log.info( f"{header}: {r.headers[header][:80]}")

    def _check_leak(self, r):
        for h in self.LEAK_HEADERS:
            if h in r.headers:
                log.warning( f"信息泄露头: {h} = {r.headers[h]}")
                self.result.add("信息泄露", "LOW",
                                f"响应头暴露版本信息: {h}={r.headers[h]}",
                                url=self.target)

    def _check_csp_quality(self, r):
        """检测 CSP 配置质量"""
        csp = r.headers.get("Content-Security-Policy", "")
        if not csp:
            return
        issues = []
        if "unsafe-inline" in csp:
            issues.append("包含 unsafe-inline（削弱 XSS 防护）")
        if "unsafe-eval" in csp:
            issues.append("包含 unsafe-eval（允许动态代码执行）")
        if "*" in csp and "src" in csp:
            issues.append("包含通配符 *（过于宽松）")
        if issues:
            log.warning( f"CSP 配置不当: {'; '.join(issues)}")
            self.result.add("安全头配置", "LOW",
                            f"CSP 配置存在缺陷: {'; '.join(issues)}",
                            url=self.target)

    def _check_cookies(self, r):
        """检测 Set-Cookie 安全属性"""
        for cookie in r.cookies:
            issues = []

            # Secure 标志
            if not cookie.secure:
                issues.append("缺少 Secure 标志")

            # HttpOnly：通过 _rest 字典检测（更可靠）
            rest = getattr(cookie, "_rest", {})
            has_httponly = any(
                k.lower() == "httponly"
                for k in rest.keys()
            )
            if not has_httponly:
                issues.append("缺少 HttpOnly 标志")

            # SameSite
            samesite = None
            for k, v in rest.items():
                if k.lower() == "samesite":
                    samesite = v
                    break
            if not samesite:
                issues.append("缺少 SameSite 属性")
            elif samesite.lower() == "none" and not cookie.secure:
                issues.append("SameSite=None 但缺少 Secure 标志")

            if issues:
                log.warning( f"Cookie [{cookie.name}]: {', '.join(issues)}")
                self.result.add("Cookie 安全", "MEDIUM",
                                f"Cookie '{cookie.name}' 安全配置不当: {', '.join(issues)}",
                                url=self.target)
