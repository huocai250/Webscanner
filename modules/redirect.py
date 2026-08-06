"""
开放重定向检测模块
Author: 火柴 | GitHub: huocai250
v4.0: 测试真实注入点 + 并发；同时检查 Location 头与 meta refresh
"""
import re
from urllib.parse import urlparse
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "return_url",
    "redirect_uri", "redirect_url", "callback", "go", "dest",
    "destination", "link", "out", "target", "to", "forward",
]

CANARY = "canary-redirect.example"
REDIRECT_PAYLOADS = [
    f"//{CANARY}",
    f"https://{CANARY}",
    f"/\\{CANARY}",
    f"https:{CANARY}",
    f"/%09/{CANARY}",
    f"///{CANARY}",
    f"////{CANARY}",
]


class OpenRedirectScanner(BaseScanner):
    name = "redirect"
    passive = False

    def run(self):
        log("INFO", "开放重定向检测（并发）...")
        targets = self._targets()
        self.map(self._test, targets)

    def _targets(self):
        out, seen = [], set()
        for ip in self.ctx.injection_points:
            for pname in ip["params"]:
                key = (ip["url"], ip["method"], pname)
                if key not in seen:
                    seen.add(key)
                    out.append((ip["url"], ip["method"], dict(ip["params"]), pname))
        for pname in REDIRECT_PARAMS:
            key = (self.target, "GET", pname)
            if key not in seen:
                seen.add(key)
                out.append((self.target, "GET", {pname: "test"}, pname))
        return out

    def _test(self, target):
        url, method, params, pname = target
        for payload in REDIRECT_PAYLOADS:
            test = dict(params); test[pname] = payload
            if method == "POST":
                r = self.post(url, data=test, allow_redirects=False)
            else:
                r = self.get(build_url(url, test), allow_redirects=False)
            if not r:
                continue
            # 1) Location 头跳转
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if self._points_to_canary(loc):
                    log("VULN", f"[开放重定向] 参数: {pname} → {loc}")
                    self.add("开放重定向", "MEDIUM",
                             f"参数 '{pname}' 存在开放重定向 (Location)",
                             f"Location: {loc} @ {url}", url=url)
                    return f"{pname}@{url}"
            # 2) meta refresh 跳转
            m = re.search(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)',
                          r.text or "", re.I)
            if m and self._points_to_canary(m.group(1)):
                log("VULN", f"[开放重定向-meta] 参数: {pname}")
                self.add("开放重定向", "MEDIUM",
                         f"参数 '{pname}' 存在开放重定向 (meta refresh)",
                         f"url={m.group(1)} @ {url}", url=url, confidence="疑似")
                return f"{pname}@{url}"
        return None

    @staticmethod
    def _points_to_canary(loc: str) -> bool:
        if not loc:
            return False
        host = urlparse(loc if "://" in loc else "http:" + loc).hostname or ""
        return CANARY in loc or host == CANARY
