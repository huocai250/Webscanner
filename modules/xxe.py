"""
XXE（XML 外部实体）注入检测模块（主动 / 带内检测）
Author: 火柴 | GitHub: huocai250

对接受 XML 的端点发送包含实体定义的 payload，通过**带内回显**判断解析器
是否处理了实体（内部实体展开 / 参数实体）。

安全边界：本模块只做**存在性检测** —— 用内部实体展开一个无害标记来判断
XML 解析器是否启用外部/参数实体处理。**不读取本地文件、不做数据外带、
不发起 SSRF**。带外(OOB)文件读取属于利用行为，本工具不实现。
"""
import re
from core.scanner import BaseScanner
from core.colors import log

MARKER = "wvsxxe31337"

# 内部实体展开：若响应回显 MARKER，说明实体被解析（带内、无害）
PROBE = f"""<?xml version="1.0"?>
<!DOCTYPE data [ <!ENTITY x "{MARKER}"> ]>
<data>&x;</data>"""

# 探测目标端点（爬虫发现的 + 常见 API 路径）
XML_PATHS = ["/", "/api", "/api/xml", "/xmlrpc.php", "/services",
             "/soap", "/ws", "/upload"]


class XXEScanner(BaseScanner):
    name = "xxe"
    passive = False

    def run(self):
        log("INFO", "XXE 注入检测（带内实体展开）...")
        endpoints = self._endpoints()
        found = self.map(self._test, endpoints)
        if not found:
            log("INFO", "  未发现可注入 XML 的端点")

    def _endpoints(self):
        eps = set()
        # 爬虫发现的注入点里，method=POST 的更可能吃 XML
        for ip in self.ctx.injection_points:
            eps.add(ip["url"])
        for p in XML_PATHS:
            eps.add(self.url(p))
        return list(eps)

    def _test(self, endpoint):
        headers = {"Content-Type": "application/xml"}
        r = self.post(endpoint, data=PROBE, headers=headers)
        if not r or not r.text:
            return None
        # 回显了展开后的实体值 => 解析器处理了实体
        if MARKER in r.text and PROBE not in r.text:
            log("VULN", f"[XXE] 端点解析 XML 实体: {endpoint}")
            self.add("XXE 注入", "HIGH",
                     "端点解析 XML 外部/内部实体（存在 XXE 风险，可能被用于文件读取/SSRF）",
                     evidence=f"内部实体展开回显 @ {endpoint}", url=endpoint,
                     confidence="疑似")
            return endpoint
        # 报错也可能指示 XML 被解析
        if re.search(r"(DOCTYPE is not allowed|external entity|XML parsing|"
                     r"SAXParseException|lxml\.etree)", r.text, re.I):
            self.add("XXE 注入", "LOW",
                     "端点返回 XML 解析相关信息，建议人工确认是否禁用外部实体",
                     evidence=endpoint, url=endpoint, confidence="疑似")
        return None
