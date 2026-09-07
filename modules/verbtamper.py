"""
HTTP 动词篡改 / 方法覆盖 / WebDAV 检测模块（主动）
Author: 火柴 | GitHub: huocai250

- 方法覆盖：X-HTTP-Method-Override / X-Method-Override 等头是否被服务端接受，
  可能绕过基于方法的访问控制。
- WebDAV：PROPFIND/MKCOL 等方法是否开启（可能允许上传/遍历）。
- 动词篡改：用非常规方法访问受限资源是否绕过限制。
仅检测方法可用性，不上传/不修改任何资源。
"""
from core.scanner import BaseScanner
from core.colors import log

OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-HTTP-Method",
                    "X-Method-Override", "X-Original-HTTP-Method"]


class VerbTamperingScanner(BaseScanner):
    name = "verbtamper"
    passive = False

    def run(self):
        log("INFO", "动词篡改 / 方法覆盖 / WebDAV 检测...")
        self._webdav()
        self._method_override()

    def _webdav(self):
        # PROPFIND 探测（只读方法，无害）
        try:
            r = self.request("PROPFIND", self.target,
                             headers={"Depth": "0"})
        except Exception:
            r = None
        if r is not None and r.status_code in (207, 200) and \
           ("multistatus" in (r.text or "").lower() or r.status_code == 207):
            log("VULN", "[WebDAV] PROPFIND 可用")
            self.add("HTTP 方法", "MEDIUM",
                     "WebDAV PROPFIND 方法开启（返回 207 Multi-Status），"
                     "可能泄露目录结构或允许 WebDAV 操作",
                     evidence=f"PROPFIND -> {r.status_code}", url=self.target,
                     confidence="确认")
        # 其它 WebDAV 方法可用性（OPTIONS 通告）
        try:
            o = self.request("OPTIONS", self.target)
        except Exception:
            o = None
        if o is not None:
            allow = o.headers.get("Allow", "") + o.headers.get("Public", "")
            dav = o.headers.get("DAV", "")
            risky = [m for m in ("PUT", "DELETE", "MKCOL", "COPY", "MOVE", "PROPPATCH")
                     if m in allow.upper()]
            if dav or risky:
                self.add("HTTP 方法", "MEDIUM",
                         f"服务端通告支持 WebDAV/写方法：{dav or ''} {' '.join(risky)}".strip(),
                         evidence=f"Allow: {allow} DAV: {dav}", url=self.target,
                         confidence="疑似")

    def _method_override(self):
        base = self.baseline(self.target)
        if not base:
            return
        for h in OVERRIDE_HEADERS:
            # 用覆盖头声明成 DELETE，但实际发 GET —— 若响应显著变化说明被解析
            r = self.get(self.target, headers={h: "DELETE"})
            if r is not None and base is not None and \
               r.status_code != base.status_code and r.status_code in (405, 501, 400, 403):
                self.add("HTTP 方法", "LOW",
                         f"服务端疑似接受方法覆盖头 '{h}'（改变了响应），"
                         "可能绕过基于 HTTP 方法的访问控制",
                         evidence=f"{h}: DELETE -> {r.status_code} (基线 {base.status_code})",
                         url=self.target, confidence="疑似")
                log("VULN", f"[方法覆盖] {h} 被解析")
                return
