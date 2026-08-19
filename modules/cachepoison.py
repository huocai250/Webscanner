"""
Web 缓存投毒指示检测模块（主动 / 非破坏）
Author: 火柴 | GitHub: huocai250

发送带有非常规请求头（X-Forwarded-Host / X-Forwarded-Scheme 等）的请求，
若这些「非缓存键」头的值被反射进响应体或响应头，且响应可缓存，则存在
缓存投毒风险。本模块只做**指示性检测**，注入无害标记值，不实际投毒缓存。
"""
from core.scanner import BaseScanner
from core.colors import log

MARKER = "wvscache1337.example"
UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Server",
    "X-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix",
]


class CachePoisonScanner(BaseScanner):
    name = "cachepoison"
    passive = False

    def run(self):
        log("INFO", "Web 缓存投毒指示检测（非缓存键头反射）...")
        base = self.baseline(self.target)
        cacheable = self._is_cacheable(base) if base else False

        for h in UNKEYED_HEADERS:
            r = self.get(self.target, headers={h: MARKER})
            if not r:
                continue
            body = r.text or ""
            hdr_blob = " ".join(f"{k}: {v}" for k, v in r.headers.items())
            if MARKER in body or MARKER in hdr_blob:
                loc = "响应体" if MARKER in body else "响应头"
                sev = "MEDIUM" if cacheable else "LOW"
                log("VULN", f"[缓存投毒-疑似] 头 {h} 被反射进{loc}")
                self.add("配置错误", sev,
                         f"非缓存键头 '{h}' 的值被反射进{loc}"
                         + ("，且响应可缓存（缓存投毒风险）" if cacheable
                            else "（若响应可缓存则存在缓存投毒风险）"),
                         evidence=f"{h}: {MARKER}", url=self.target,
                         confidence="疑似")

    @staticmethod
    def _is_cacheable(r):
        cc = r.headers.get("Cache-Control", "").lower()
        if any(x in cc for x in ("no-store", "no-cache", "private")):
            return False
        # 有缓存相关头或 CDN 缓存命中头 => 视为可缓存
        return any(k.lower() in ("cache-control", "expires", "age", "x-cache",
                                 "cf-cache-status") for k in r.headers.keys())
