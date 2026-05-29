"""
XSS 检测模块（反射型 / DOM型 / SSTI）
Author: 火柴 | GitHub: huocai250
"""
import re
from utils.http import extract_forms
from core.scanner import BaseScanner
from core.colors import log

REFLECTED_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
]

SSTI_PAYLOADS = {
    "{{7*7}}":          "49",      # Jinja2 / Twig
    "${7*7}":           "49",      # FreeMarker / Thymeleaf
    "#{7*7}":           "49",      # Ruby ERB / Slim
    "<%= 7*7 %>":       "49",      # EJS / ERB
    "{{7*'7'}}":        "7777777", # Jinja2
    "{{'7'*7}}":        "7777777",
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
    def run(self):
        log("INFO", "XSS 检测（反射型 / SSTI / DOM 分析）...")
        r = self.get(self.target)
        if not r:
            return
        self._test_reflected(COMMON_PARAMS, r)
        self._test_ssti(COMMON_PARAMS)
        self._check_dom(r.text)
        forms = extract_forms(r.text)
        for i, form in enumerate(forms):
            self._test_form_xss(form, i)

    def _test_reflected(self, params, base_r=None):
        for param in params:
            for payload in REFLECTED_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and payload in r.text:
                    # 确认 payload 是否在 HTML 上下文中未被编码
                    if not self._is_encoded(payload, r.text):
                        log("VULN", f"[反射型XSS] 参数: {param} | Payload: {payload[:40]}")
                        self.result.add("XSS", "HIGH",
                                        f"[反射型XSS] 参数 '{param}' 未过滤直接输出",
                                        f"Payload: {payload}", url=self.target)
                        break

    def _test_ssti(self, params):
        for param in params:
            for payload, expected in SSTI_PAYLOADS.items():
                r = self.get(self.target, params={param: payload})
                if r and expected in r.text:
                    log("VULN", f"[SSTI] 参数: {param} | Payload: {payload} → {expected}")
                    self.result.add("SSTI", "CRITICAL",
                                    f"[模板注入] 参数 '{param}' 存在服务端模板注入",
                                    f"Payload: {payload} 输出: {expected}", url=self.target)
                    return

    def _test_form_xss(self, form, idx):
        action = form["action"] or self.target
        if not action.startswith("http"):
            action = self.url(action)
        for param in form["inputs"]:
            for payload in REFLECTED_PAYLOADS[:4]:
                data = form["inputs"].copy()
                data[param] = payload
                if form["method"] == "POST":
                    r = self.post(action, data=data)
                else:
                    r = self.get(action, params=data)
                if r and payload in r.text and not self._is_encoded(payload, r.text):
                    log("VULN", f"[存储/反射XSS] 表单#{idx} 参数: {param}")
                    self.result.add("XSS", "HIGH",
                                    f"[XSS] 表单 #{idx} 参数 '{param}' 存在 XSS",
                                    f"Payload: {payload}", url=action)
                    break

    def _check_dom(self, html):
        """DOM XSS 风险分析"""
        found = [i for i in DOM_INDICATORS if i in html]
        if len(found) >= 2:
            log("WARN", f"页面存在 DOM XSS 风险点: {', '.join(found[:4])}")
            self.result.add("XSS", "LOW",
                            f"页面存在可能的 DOM XSS 风险: {', '.join(found[:4])}",
                            url=self.target)

    def _is_encoded(self, payload, text):
        """简单检测 payload 是否被 HTML 编码"""
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        return encoded in text and payload not in text
