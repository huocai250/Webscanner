"""
CSP 深度评估 / Cookie 深度分析模块（被动）
Author: 火柴 | GitHub: huocai250
"""
import re
from core.scanner import BaseScanner
from core.colors import log

# 已知可被绕过的 CSP 白名单域（JSONP/AngularJS 等）
BYPASS_HOSTS = [
    "ajax.googleapis.com", "www.google.com", "*.googleapis.com",
    "cdnjs.cloudflare.com", "ajax.aspnetcdn.com", "unpkg.com",
    "cdn.jsdelivr.net", "*.cloudflare.com",
]


class CSPScanner(BaseScanner):
    name = "csp"
    passive = True

    def run(self):
        log("INFO", "CSP 深度评估...")
        r = self.baseline(self.target)
        if not r:
            return
        headers = {k.lower(): v for k, v in r.headers.items()}
        csp = headers.get("content-security-policy", "")
        cspro = headers.get("content-security-policy-report-only", "")
        if not csp and cspro:
            self.add("配置错误", "LOW",
                     "仅设置了 CSP-Report-Only（不强制拦截），XSS 防护无实际效果",
                     url=self.target, confidence="疑似")
            return
        if not csp:
            return  # 缺失由 headers 模块负责

        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            toks = part.split()
            directives[toks[0].lower()] = toks[1:]

        low = csp.lower()
        issues = []
        if "default-src" not in directives and "script-src" not in directives:
            issues.append("缺少 default-src/script-src（几乎不限制脚本）")
        if "object-src" not in directives and "'none'" not in low:
            issues.append("未设置 object-src 'none'（可加载插件/flash）")
        if "base-uri" not in directives:
            issues.append("缺少 base-uri（可被 <base> 劫持注入）")
        if "frame-ancestors" not in directives:
            issues.append("缺少 frame-ancestors（点击劫持防护不足）")
        script = " ".join(directives.get("script-src", []) + directives.get("default-src", []))
        for host in BYPASS_HOSTS:
            if host.replace("*.", "") in script:
                issues.append(f"script-src 白名单含可绕过域 {host}")
                break
        if "'unsafe-inline'" in script and "'nonce-" not in script and "'strict-dynamic'" not in script:
            issues.append("script-src 含 unsafe-inline 且无 nonce/strict-dynamic")

        if issues:
            self.add("配置错误", "LOW",
                     "CSP 策略存在弱点：" + "；".join(issues[:5]),
                     evidence=csp[:150], url=self.target, confidence="疑似")
            log("VULN", f"[CSP] {len(issues)} 项弱点")


class CookieScanner(BaseScanner):
    name = "cookiesec"
    passive = True

    def run(self):
        log("INFO", "Cookie 深度分析（前缀/SameSite/作用域）...")
        r = self.baseline(self.target)
        if not r:
            return
        set_cookies = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
        # requests 合并多个 Set-Cookie 到一个头，用 raw 分割
        raw = r.headers.get("Set-Cookie", "")
        if raw and raw not in set_cookies:
            set_cookies = [raw]
        for sc in set_cookies:
            self._analyze(sc)

    def _analyze(self, sc):
        name = sc.split("=", 1)[0].strip()
        low = sc.lower()
        is_https = self.target.startswith("https")

        # __Secure- / __Host- 前缀规范
        if name.startswith("__Host-"):
            if "secure" not in low or "path=/" not in low or "domain=" in low:
                self.add("Cookie 安全", "LOW",
                         f"Cookie '{name}' 使用 __Host- 前缀但不满足其要求"
                         "（须 Secure、Path=/、无 Domain）", url=self.target, confidence="疑似")
        if name.startswith("__Secure-") and "secure" not in low:
            self.add("Cookie 安全", "MEDIUM",
                     f"Cookie '{name}' 使用 __Secure- 前缀但缺少 Secure 标志",
                     url=self.target, confidence="疑似")
        # SameSite=None 必须 Secure
        if "samesite=none" in low and "secure" not in low:
            self.add("Cookie 安全", "MEDIUM",
                     f"Cookie '{name}' 设置 SameSite=None 但缺少 Secure（现代浏览器将拒绝）",
                     url=self.target, confidence="确认")
            log("VULN", f"[Cookie] {name} SameSite=None 无 Secure")
        # 过宽的 Domain 作用域
        m = re.search(r'domain=\.?([^;]+)', low)
        if m and m.group(1).count(".") == 1:
            self.add("Cookie 安全", "LOW",
                     f"Cookie '{name}' 的 Domain 作用域较宽（{m.group(1).strip()}），"
                     "会共享给所有子域", url=self.target, confidence="信息")
