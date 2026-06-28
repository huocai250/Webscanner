"""
注入类漏洞检测（Log4Shell / Host Header 注入 / CRLF 注入）
Author: 火柴 | GitHub: huocai250

修复:
- 使用 BaseScanner.get 和 request 方法（享受重试机制）
- Host Header 测试需要禁用重定向
- CRLF 注入改进检测逻辑
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
from core.scanner import BaseScanner

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://127.0.0.1:1389/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1/a}",
    "${jndi:dns://127.0.0.1/a}",
    "${${lower:j}ndi:${lower:l}dap://127.0.0.1/a}",
]

LOG4SHELL_INJECT_HEADERS = [
    "User-Agent", "X-Forwarded-For", "X-Api-Version",
    "X-Forwarded-Host", "Referer", "X-Client-IP",
    "CF-Connecting-IP", "X-Real-IP", "X-Originating-IP",
]

HOST_HEADER_PAYLOADS = [
    "evil.com",
    "evil.com:80",
    "legit.com@evil.com",
    "legit.com.evil.com",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20injected_by_scanner=1",
    "%0aSet-Cookie:%20injected_by_scanner=1",
    "%0d%0a%20Set-Cookie:%20injected_by_scanner=1",
    "\r\nSet-Cookie: injected_by_scanner=1",
    "\nSet-Cookie: injected_by_scanner=1",
]

CRLF_PARAMS = ["redirect", "url", "next", "return", "q", "search", "returnUrl"]


class InjectionScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info( "注入检测（Log4Shell / Host Header / CRLF）...")
        self._check_log4shell()
        self._check_host_header()
        self._check_crlf()
        self._log_module_done("Log4Shell/CRLF/Host Header", _before)

    def _check_log4shell(self):
        for payload in LOG4SHELL_PAYLOADS[:2]:
            for header in LOG4SHELL_INJECT_HEADERS:
                r = self.get(self.target, headers={header: payload})
                if not r:
                    continue
                # 服务器返回 500 或将 payload 原样反射（未过滤）
                if r.status_code == 500:
                    log.warning( f"[Log4Shell] Header '{header}' 注入触发 500，疑似存在漏洞")
                    self.result.add("Log4Shell", "HIGH",
                                    f"Header '{header}' 注入 JNDI Payload 触发服务器错误",
                                    f"Payload: {payload}", url=self.target)
                    return
                if "${jndi" in r.text:
                    log.warning( "[Log4Shell] JNDI Payload 未被过滤（反射在响应中）")
                    self.result.add("Log4Shell", "HIGH",
                                    "JNDI Payload 在响应中未被过滤，疑似 Log4Shell",
                                    url=self.target)
                    return
        log.info( "Log4Shell 检测完成")

    def _check_host_header(self):
        orig_host = self.target.split("//")[-1].split("/")[0]
        for payload in HOST_HEADER_PAYLOADS:
            # 修复：禁用重定向，直接观察响应
            r = self.get(self.target,
                         headers={"Host": payload},
                         allow_redirects=False)
            if not r:
                continue
            # payload 被反射到响应 body
            if payload.split(":")[0] in r.text:
                log.warning("[VULN] " +  f"[Host Header注入] Payload 被反射到响应: {payload}")
                self.result.add("Host Header 注入", "MEDIUM",
                                "Host Header 值被反射到响应中",
                                f"Payload: {payload}", url=self.target)
                return
            # payload 被反射到 Location 头
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                log.warning("[VULN] " +  f"[Host Header注入] 影响 Location 重定向: {loc}")
                self.result.add("Host Header 注入", "HIGH",
                                "Host Header 注入影响重定向目标",
                                f"Location: {loc}", url=self.target)
                return
        log.info( "Host Header 注入检测完成")

    def _check_crlf(self):
        for param in CRLF_PARAMS:
            for payload in CRLF_PAYLOADS:
                r = self.get(self.target,
                             params={param: "https://example.com" + payload},
                             allow_redirects=False)
                if not r:
                    continue
                # 检测注入的 Cookie 是否出现在响应头
                set_cookie = r.headers.get("Set-Cookie", "")
                location   = r.headers.get("Location",  "")
                if "injected_by_scanner" in set_cookie:
                    log.warning("[VULN] " +  f"[CRLF注入] 参数 '{param}' 注入成功，Set-Cookie 被篡改")
                    self.result.add("CRLF 注入", "HIGH",
                                    f"参数 '{param}' 存在 CRLF 注入，可注入任意响应头",
                                    f"Payload: {payload}", url=self.target)
                    return
                if "\r\n" in location or "%0d%0a" in location.lower():
                    log.warning("[VULN] " +  f"[CRLF注入] Location 头含 CRLF 字符")
                    self.result.add("CRLF 注入", "MEDIUM",
                                    f"Location 头含 CRLF 字符，存在 HTTP 响应拆分风险",
                                    url=self.target)
                    return
        log.info( "CRLF 注入检测完成")
