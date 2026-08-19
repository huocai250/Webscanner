"""
前端安全检测模块（被动）
Author: 火柴 | GitHub: huocai250

检测客户端侧的常见安全问题：
  - 外部脚本缺少 SRI（子资源完整性）
  - HTTPS 页面加载 HTTP 资源（混合内容）
  - CSP 质量问题（unsafe-inline / unsafe-eval / 通配符）
"""
import re
from urllib.parse import urlparse
from core.scanner import BaseScanner
from core.colors import log


class FrontendScanner(BaseScanner):
    name = "frontend"
    passive = True

    def run(self):
        log("INFO", "前端安全检测（SRI/混合内容/CSP 质量）...")
        r = self.baseline(self.target)
        if not r:
            return
        html = r.text or ""
        is_https = urlparse(r.url).scheme == "https"

        self._sri(html)
        if is_https:
            self._mixed_content(html)
        self._csp_quality({k.lower(): v for k, v in r.headers.items()})

    def _sri(self, html):
        ext = 0
        for m in re.finditer(r'<script([^>]+)>', html, re.I):
            attrs = m.group(1)
            src = re.search(r'src=["\']([^"\']+)["\']', attrs, re.I)
            if not src:
                continue
            # 仅关注跨域外链脚本
            host = urlparse(src.group(1)).netloc
            if host and host != urlparse(self.target).netloc:
                if "integrity=" not in attrs.lower():
                    ext += 1
        if ext:
            self.add("配置错误", "LOW",
                     f"有 {ext} 个跨域外部脚本未使用 SRI（integrity），"
                     "第三方被攻破时可能注入恶意代码",
                     url=self.target, confidence="疑似")
            log("VULN", f"[前端] {ext} 个外链脚本缺少 SRI")

    def _mixed_content(self, html):
        http_res = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', html, re.I)
        http_res = [u for u in http_res if not u.startswith("http://localhost")]
        if http_res:
            self.add("配置错误", "MEDIUM",
                     f"HTTPS 页面加载了 {len(http_res)} 个 HTTP 资源（混合内容），"
                     "可被中间人篡改",
                     evidence=http_res[0][:80], url=self.target)
            log("VULN", f"[前端] 混合内容 {len(http_res)} 处")

    def _csp_quality(self, headers):
        csp = headers.get("content-security-policy", "")
        if not csp:
            return  # 缺失由 headers 模块负责
        issues = []
        low = csp.lower()
        if "unsafe-inline" in low:
            issues.append("含 unsafe-inline")
        if "unsafe-eval" in low:
            issues.append("含 unsafe-eval")
        if re.search(r"(default-src|script-src)[^;]*\*", low):
            issues.append("script/default-src 使用通配符 *")
        if issues:
            self.add("配置错误", "LOW",
                     f"CSP 策略较弱：{'; '.join(issues)}（削弱了 XSS 防护）",
                     evidence=csp[:120], url=self.target, confidence="疑似")
            log("VULN", f"[前端] CSP 质量问题: {', '.join(issues)}")
