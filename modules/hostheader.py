"""
Host 头注入检测模块（新增）
Author: 火柴 | GitHub: huocai250
检测应用是否信任 Host / X-Forwarded-Host 头（可导致密码重置投毒、缓存投毒等）
"""
from core.scanner import BaseScanner
from core.colors import log

EVIL_HOST = "injected-host.example"


class HostHeaderScanner(BaseScanner):
    name = "hostheader"
    passive = True

    def run(self):
        log("INFO", "Host 头注入检测...")
        self._test_host_reflection()
        self._test_xfh()

    def _test_host_reflection(self):
        r = self.get(self.target, headers={"Host": EVIL_HOST})
        if not r:
            return
        # 恶意 Host 出现在响应体（如绝对链接）或重定向 Location 中
        loc = r.headers.get("Location", "")
        if EVIL_HOST in (r.text or "") or EVIL_HOST in loc:
            where = "Location 头" if EVIL_HOST in loc else "响应体"
            log("VULN", f"Host 头被信任并反射到{where}")
            self.add("Host 头注入", "MEDIUM",
                     f"应用信任 Host 头并将其反射到{where}，"
                     f"可能导致密码重置投毒 / 缓存投毒",
                     f"注入 Host: {EVIL_HOST}", url=self.target, confidence="疑似")

    def _test_xfh(self):
        r = self.get(self.target, headers={"X-Forwarded-Host": EVIL_HOST})
        if not r:
            return
        loc = r.headers.get("Location", "")
        if EVIL_HOST in loc or EVIL_HOST in (r.text or ""):
            log("VULN", "X-Forwarded-Host 被信任并反射")
            self.add("Host 头注入", "MEDIUM",
                     "应用信任 X-Forwarded-Host 头，可能导致链接投毒",
                     f"X-Forwarded-Host: {EVIL_HOST}", url=self.target, confidence="疑似")
