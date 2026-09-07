"""
敏感路径暴露扫描模块（主动）
Author: 火柴 | GitHub: huocai250

对 core/data/exposures.py 中收录的数百个公开已知敏感路径做存在性检测，
采用「软 404 基线对比 + 内容签名」降低误报。仅检测暴露，不做利用。
"""
from core.scanner import BaseScanner
from core.colors import log
from core.data.exposures import EXPOSURES

CATEGORY_BY_SEV = {
    "CRITICAL": "敏感信息泄露", "HIGH": "敏感信息泄露",
    "MEDIUM": "文件暴露", "LOW": "信息泄露", "INFO": "信息泄露",
}


class ExposureScanner(BaseScanner):
    name = "exposure"
    passive = False   # 会对大量路径发起请求

    def run(self):
        log("INFO", f"敏感路径暴露扫描（{len(EXPOSURES)} 条，并发）...")
        self.calibrate_soft404()
        found = self.map(self._check, EXPOSURES)
        log("OK", f"暴露扫描完成，发现 {len(found)} 处暴露")

    def _check(self, entry):
        path, sev, signatures = entry
        r = self.probe_get(self.url(path))
        if r is None or r.status_code != 200:
            return None
        body = r.text or ""

        if signatures:
            # 需命中内容签名
            blob = body + "\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            if not any(sig in blob for sig in signatures):
                return None
        else:
            # 无签名：靠软 404 相似度过滤
            if self.is_soft404(r):
                return None
            if len(body) == 0:
                # 空 200 也可能有意义（如某些二进制文件），仅对无签名项要求非空
                return None

        cat = CATEGORY_BY_SEV.get(sev, "信息泄露")
        conf = "确认" if signatures else "疑似"
        log("VULN", f"[暴露] {path} ({sev})")
        self.add(cat, sev, f"敏感路径暴露: /{path}",
                 evidence=f"HTTP 200 @ /{path}", url=r.url, confidence=conf)
        return path
