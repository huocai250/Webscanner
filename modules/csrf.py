"""
CSRF 检测模块
Author: 火柴 | GitHub: huocai250
v4.0: 复用爬虫抓取的页面（基线），检测所有 POST 表单
"""
import re
from utils.http import extract_forms
from core.scanner import BaseScanner
from core.colors import log


class CSRFScanner(BaseScanner):
    name = "csrf"
    passive = True

    TOKEN_PATTERNS = re.compile(
        r'(csrf|token|nonce|_token|authenticity_token|__requestverificationtoken)',
        re.I)

    def run(self):
        log("INFO", "CSRF 检测...")
        r = self.baseline()
        if not r:
            return
        forms = extract_forms(r.text, self.target)
        post_forms = [f for f in forms if f["method"] == "POST"]
        if not post_forms:
            log("SKIP", "未发现 POST 表单")
            return
        for i, form in enumerate(post_forms):
            has_token = bool(self.TOKEN_PATTERNS.search(
                str(form["inputs"]) + str(r.text)))
            if not has_token:
                log("VULN", f"表单 #{i+1} 缺少 CSRF Token")
                self.add("CSRF", "MEDIUM",
                         f"POST 表单 #{i+1} 未检测到 CSRF Token，可能存在 CSRF 漏洞",
                         url=form["action"] or self.target, confidence="疑似")
            else:
                log("OK", f"表单 #{i+1} 存在 CSRF Token")
