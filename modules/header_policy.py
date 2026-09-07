"""
安全响应头策略深度检测模块（被动）
Author: 火柴 | GitHub: huocai250

在基础安全头之外，检查现代隔离/策略类响应头是否配置：
  Permissions-Policy、Referrer-Policy、Cross-Origin-Opener-Policy (COOP)、
  Cross-Origin-Embedder-Policy (COEP)、Cross-Origin-Resource-Policy (CORP)、
  以及限流相关头（X-RateLimit-*/Retry-After）的存在性提示。
这些属「纵深防御/最佳实践」，缺失多为 LOW/INFO 级。
"""
from core.scanner import BaseScanner
from core.colors import log

CHECKS = [
    ("referrer-policy", "Referrer-Policy", "LOW",
     "缺少 Referrer-Policy，跳转时可能泄露完整 URL（含敏感参数）到第三方"),
    ("permissions-policy", "Permissions-Policy", "LOW",
     "缺少 Permissions-Policy，未限制摄像头/麦克风/地理位置等强能力特性"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "LOW",
     "缺少 COOP，跨源窗口隔离不足（利于 XS-Leaks/Spectre 类攻击）"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy", "LOW",
     "缺少 CORP，资源可被任意跨源站点嵌入读取"),
]


class HeaderPolicyScanner(BaseScanner):
    name = "headerpolicy"
    passive = True

    def run(self):
        log("INFO", "安全响应头策略深度检测（Referrer/Permissions/COOP/CORP 等）...")
        r = self.baseline(self.target)
        if not r:
            return
        headers = {k.lower(): v for k, v in r.headers.items()}
        missing = []
        for key, label, sev, desc in CHECKS:
            if key not in headers:
                missing.append((label, sev, desc))
        for label, sev, desc in missing:
            self.add("安全头缺失", sev, desc, evidence=f"缺少 {label}",
                     url=self.target, confidence="确认")
        if missing:
            log("VULN", f"[头策略] 缺少 {len(missing)} 个隔离/策略头")

        # COEP 仅在设置了 COOP 时才有意义，单独轻提示
        if "cross-origin-opener-policy" in headers and \
           "cross-origin-embedder-policy" not in headers:
            self.add("安全头缺失", "INFO",
                     "已设置 COOP 但未设置 COEP，跨源隔离(crossOriginIsolated)不会生效",
                     url=self.target, confidence="信息")

        # 限流头存在性（信息级）——不主动打请求测试限流，只看是否声明
        has_rl = any(k in headers for k in
                     ("x-ratelimit-limit", "ratelimit-limit", "retry-after",
                      "x-rate-limit-limit"))
        if not has_rl:
            self.add("信息泄露", "INFO",
                     "响应未见限流相关头（X-RateLimit-*/Retry-After）；"
                     "建议对登录/接口等敏感端点实施限流（此为提示，未做压力测试）",
                     url=self.target, confidence="信息")
