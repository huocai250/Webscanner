"""
开放重定向检测模块
Author: 火柴 | GitHub: huocai250
"""
from core.scanner import BaseScanner
from core.colors import log

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "return_url",
    "redirect_uri", "redirect_url", "callback", "go", "dest",
    "destination", "link", "out", "target", "to", "forward",
]

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    "/\\evil.com",
    "https:evil.com",
    "/%09/evil.com",
    "//%09/evil.com",
    "///evil.com",
    "////evil.com",
]


class OpenRedirectScanner(BaseScanner):
    def run(self):
        log("INFO", "开放重定向检测...")
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                r = self.get(self.target, params={param: payload},
                             allow_redirects=False)
                if not r:
                    continue
                if r.status_code in [301, 302, 303, 307, 308]:
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc or (loc.startswith("//") and "evil" in loc):
                        log("VULN", f"[开放重定向] 参数: {param} → {loc}")
                        self.result.add("开放重定向", "MEDIUM",
                                        f"参数 '{param}' 存在开放重定向",
                                        f"Location: {loc}", url=self.target)
                        return
