"""
CRLF 注入 / HTTP 响应拆分检测模块（主动）
Author: 火柴 | GitHub: huocai250

向参数注入 CRLF 序列，若能在响应头中注入自定义头，则存在 CRLF 注入
（可导致响应拆分、缓存投毒、会话固定等）。检测为**带内**，只注入一个无害
标记头，不构造恶意响应体。
"""
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

MARKER = "wvscrlf"
PAYLOADS = [
    f"%0d%0a{MARKER}: 1",
    f"%0D%0A{MARKER}: 1",
    f"%E5%98%8A%E5%98%8D{MARKER}: 1",   # Unicode 变体绕过
    f"test%0d%0a{MARKER}: 1",
    f"%0a{MARKER}: 1",
]


class CRLFScanner(BaseScanner):
    name = "crlf"
    passive = False

    def run(self):
        log("INFO", "CRLF 注入 / 响应拆分检测（并发）...")
        targets = self.injection_targets(common_params=["url", "redirect", "next",
                                                        "page", "q", "lang", "r"])
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        for payload in PAYLOADS:
            test = dict(params)
            test[pname] = payload
            if method == "POST":
                r = self.post(url, data=test, allow_redirects=False)
            else:
                r = self.get(build_url(url, test), allow_redirects=False)
            if not r:
                continue
            # 注入的头是否出现在响应头里
            if MARKER in {k.lower() for k in r.headers.keys()}:
                log("VULN", f"[CRLF 注入] 参数: {pname}")
                self.add("CRLF 注入", "HIGH",
                         f"参数 '{pname}' 存在 CRLF 注入，可注入响应头（响应拆分）",
                         evidence=f"注入头 {MARKER} @ {url}", url=url)
                return f"{pname}@{url}"
        return None
