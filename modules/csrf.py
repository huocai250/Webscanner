"""
CSRF 检测模块
Author: 火柴 | GitHub: huocai250
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
from utils.http import extract_forms
from core.scanner import BaseScanner


class CSRFScanner(BaseScanner):
    TOKEN_PATTERNS = re.compile(
        r'(csrf|token|nonce|_token|authenticity_token|__requestverificationtoken)',
        re.I)

    def run(self):
        log.info( "CSRF 检测...")
        r = self.get(self.target)
        if not r:
            return
        forms = extract_forms(r.text)
        if not forms:
            log.info("[SKIP] " +  "未发现 HTML 表单")
            return
        for i, form in enumerate(forms):
            if form["method"] != "POST":
                continue
            has_token = bool(self.TOKEN_PATTERNS.search(
                str(form["inputs"]) + str(r.text)))
            if not has_token:
                log.warning("[VULN] " +  f"表单 #{i+1} 缺少 CSRF Token")
                self.result.add("CSRF", "MEDIUM",
                                f"POST 表单 #{i+1} 未检测到 CSRF Token，可能存在 CSRF 漏洞",
                                url=self.target)
            else:
                log.info( f"表单 #{i+1} 存在 CSRF Token")
