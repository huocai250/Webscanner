"""
HTTP 方法检测模块（新增）
Author: 火柴 | GitHub: huocai250
检测危险 HTTP 方法是否启用：PUT / DELETE / TRACE / CONNECT / WebDAV
"""
from core.scanner import BaseScanner
from core.colors import log

DANGEROUS = {
    "PUT":     ("HIGH",   "PUT 方法可能允许上传任意文件"),
    "DELETE":  ("HIGH",   "DELETE 方法可能允许删除服务器资源"),
    "TRACE":   ("MEDIUM", "TRACE 方法启用，存在 XST（跨站追踪）风险"),
    "CONNECT": ("MEDIUM", "CONNECT 方法启用，可能被用作代理"),
    "PATCH":   ("LOW",    "PATCH 方法启用"),
}
WEBDAV = ["PROPFIND", "MKCOL", "COPY", "MOVE"]


class MethodScanner(BaseScanner):
    name = "methods"
    passive = True   # OPTIONS 探测 + 单次危险方法测试，侵入性低

    def run(self):
        log("INFO", "HTTP 方法检测...")
        allowed = self._options()
        self._probe_dangerous(allowed)

    def _options(self):
        r = self.request("OPTIONS", self.target)
        if not r:
            return set()
        allow = r.headers.get("Allow", "") + "," + r.headers.get("Access-Control-Allow-Methods", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        if methods:
            log("OK", f"OPTIONS 返回允许方法: {', '.join(sorted(methods))}")
            self.add("HTTP 方法", "INFO",
                     f"OPTIONS 公布的允许方法: {', '.join(sorted(methods))}",
                     url=self.target, confidence="信息")
        # WebDAV 迹象
        dav = [m for m in WEBDAV if m in methods]
        if dav or "Dav" in r.headers:
            log("WARN", "检测到 WebDAV 方法迹象")
            self.add("HTTP 方法", "MEDIUM",
                     f"疑似启用 WebDAV: {', '.join(dav) or r.headers.get('Dav','')}",
                     url=self.target, confidence="疑似")
        return methods

    def _probe_dangerous(self, advertised):
        for method, (severity, desc) in DANGEROUS.items():
            r = self.request(method, self.target)
            if r is None:
                continue
            # 200/201/204 说明方法被真正接受（而非 405/501）
            if r.status_code in (200, 201, 204) or method in advertised:
                if r.status_code in (405, 501):
                    continue
                log("VULN", f"危险方法启用: {method} (HTTP {r.status_code})")
                self.add("HTTP 方法", severity,
                         f"{desc}（返回 {r.status_code}）",
                         f"{method} {self.target} → {r.status_code}", url=self.target,
                         confidence="疑似")
