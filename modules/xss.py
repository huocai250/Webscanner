"""
XSS 检测模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[优化] 集成 XSSExploiter 自动利用
[优化] 统一使用 logging
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")

import re
from utils.http import extract_forms
from core.scanner import BaseScanner


REFLECTED_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
]

SSTI_PAYLOADS = {
    "{{7*7}}": "49", "${7*7}": "49",
    "#{7*7}":  "49", "{{7*'7'}}": "7777777",
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
        _before = self.result.total()
        log.info("XSS 检测（反射型 / SSTI / DOM 分析）...")
        r = self.get(self.target)
        if not r:
            return
        self._test_reflected(COMMON_PARAMS)
        self._test_ssti(COMMON_PARAMS)
        self._check_dom(r.text)
        for i, form in enumerate(extract_forms(r.text)):
            self._test_form_xss(form, i)
        self._log_module_done("XSS", _before)

    def _test_reflected(self, params):
        for param in params:
            for payload in REFLECTED_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and payload in r.text and not self._is_encoded(payload, r.text):
                    log.warning(f"[VULN][反射型XSS] 参数: {param}")
                    exploit_result = ""
                    if self.exploit_mode:
                        exploit_result = self._run_exploit(self.target, param, "GET", {param: "test"})
                    self.result.add("XSS", "HIGH",
                                    f"[反射型XSS] 参数 '{param}' 未过滤直接输出",
                                    f"Payload: {payload}", url=self.target,
                                    exploit_result=exploit_result)
                    break

    def _test_ssti(self, params):
        for param in params:
            for payload, expected in SSTI_PAYLOADS.items():
                r = self.get(self.target, params={param: payload})
                if r and expected in r.text:
                    log.warning(f"[VULN][SSTI] 参数: {param} → 输出 {expected}")
                    self.result.add("SSTI", "CRITICAL",
                                    f"[模板注入] 参数 '{param}' 存在 SSTI",
                                    f"Payload: {payload} → {expected}",
                                    url=self.target)
                    return

    def _test_form_xss(self, form, idx):
        action = form["action"] or self.target
        if not action.startswith("http"):
            action = self.build_url(action)
        for param in form["inputs"]:
            for payload in REFLECTED_PAYLOADS[:4]:
                data = form["inputs"].copy()
                data[param] = payload
                r = (self.post(action, data=data) if form["method"] == "POST"
                     else self.get(action, params=data))
                if r and payload in r.text and not self._is_encoded(payload, r.text):
                    log.warning(f"[VULN][XSS] 表单#{idx} 参数: {param}")
                    exploit_result = ""
                    if self.exploit_mode:
                        exploit_result = self._run_exploit(action, param,
                                                          form["method"], form["inputs"])
                    self.result.add("XSS", "HIGH",
                                    f"[XSS] 表单#{idx} 参数 '{param}'",
                                    f"Payload: {payload}", url=action,
                                    exploit_result=exploit_result)
                    break

    def _check_dom(self, html):
        found = [i for i in DOM_INDICATORS if i in html]
        if len(found) >= 2:
            log.warning(f"[VULN][DOM XSS] 风险点: {', '.join(found[:4])}")
            self.result.add("XSS", "LOW",
                            f"DOM XSS 风险: {', '.join(found[:4])}",
                            url=self.target)

    def _run_exploit(self, url, param, method, base_params) -> str:
        try:
            from modules.exploit.xss_exploit import XSSExploiter
            exploiter = XSSExploiter(self)
            info = exploiter.exploit(url, param, method, base_params)
            lines = [f"PoC URL: {info.get('poc_url','N/A')[:120]}"]
            if info.get("confirmed_payload"):
                lines.append(f"确认Payload: {info['confirmed_payload'][:80]}")
            if info.get("cookie_steal_payload"):
                lines.append(f"Cookie窃取: {info['cookie_steal_payload'][:100]}")
            lines.append(f"HttpOnly: {info.get('httponly', 'unknown')}")
            return "\n".join(lines)
        except Exception as e:
            log.debug(f"XSS 利用异常: {e}")
            return f"利用失败: {e}"

    def _is_encoded(self, payload, text):
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        return encoded in text and payload not in text
