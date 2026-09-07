"""
原型链污染 / 表达式(EL/OGNL)注入检测模块（主动）
Author: 火柴 | GitHub: huocai250
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url


class ProtoPollutionScanner(BaseScanner):
    name = "protopollution"
    passive = False

    def run(self):
        log("INFO", "原型链污染检测（__proto__ 探针）...")
        endpoints = {ip["url"] for ip in self.ctx.injection_points} or {self.target}
        self.map(self._test, list(endpoints))

    def _test(self, url):
        marker = "wvspp99"
        # 1) JSON body 污染
        for body in ({"__proto__": {"wvsppkey": marker}},
                     {"constructor": {"prototype": {"wvsppkey": marker}}}):
            r = self.post(url, json=body)
            if r and r.text and self._polluted(r.text, marker):
                self._report(url, "JSON __proto__")
                return url
        # 2) 查询串污染
        r = self.get(build_url(url, {"__proto__[wvsppkey]": marker}))
        if r and r.text and self._polluted(r.text, marker):
            self._report(url, "query __proto__")
            return url
        # 3) 原型相关错误
        r2 = self.post(url, json={"__proto__": {"toString": marker}})
        if r2 and re.search(r"(prototype|__proto__).{0,40}(error|exception|invalid)",
                            r2.text or "", re.I):
            self.add("信息泄露", "LOW",
                     f"端点对 __proto__ 输入产生异常，疑似受原型链污染影响",
                     evidence=url, url=url, confidence="信息")
        return None

    @staticmethod
    def _polluted(text, marker):
        # 污染的键值回显进 JSON（弱信号）
        return marker in text and "wvsppkey" in text

    def _report(self, url, vec):
        log("VULN", f"[原型污染] {vec} @ {url}")
        self.add("配置错误", "MEDIUM",
                 f"疑似原型链污染（{vec}）：注入的原型属性影响了响应，"
                 "可能被用于绕过校验/属性注入",
                 evidence=url, url=url, confidence="疑似")


class ELInjectionScanner(BaseScanner):
    name = "eli"
    passive = False

    # EL/OGNL/SpEL 专用标记（与通用 SSTI 区分：聚焦 ${}/%{}/#{} 语法与错误特征）
    PAYLOADS = [
        ("${7*7}", "49"), ("%{7*7}", "49"), ("#{7*7}", "49"),
        ("${{7*7}}", "49"), ("${7*'7'}", None),
    ]
    ERRORS = [
        r"ognl\.", r"OgnlException", r"El(Parse)?Exception",
        r"SpelEvaluationException", r"javax\.el\.", r"freemarker\.core",
        r"Method .* threw exception",
    ]
    PARAMS = ["id", "name", "q", "search", "lang", "message", "redirect", "class"]

    def run(self):
        log("INFO", "表达式(EL/OGNL/SpEL)注入检测（并发）...")
        targets = self.injection_targets(self.PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        for payload, expect in self.PAYLOADS:
            test = dict(params); test[pname] = payload
            r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
            if not r or not r.text:
                continue
            body = r.text
            if expect and expect in body and payload not in body:
                log("VULN", f"[EL注入] 参数 {pname}（表达式求值 {payload}->{expect}）")
                self.add("SSTI", "HIGH",
                         f"参数 '{pname}' 存在表达式注入（{payload} 被求值为 {expect}）",
                         evidence=f"{payload}->{expect} @ {url}", url=url)
                return f"{pname}@{url}"
            for sign in self.ERRORS:
                if re.search(sign, body, re.I):
                    self.add("SSTI", "MEDIUM",
                             f"参数 '{pname}' 触发表达式引擎错误，疑似 EL/OGNL 注入",
                             evidence=f"命中 '{sign}' @ {url}", url=url, confidence="疑似")
                    return f"{pname}@{url}"
        return None
