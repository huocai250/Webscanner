"""
安全配置错误检测模块（被动）
Author: 火柴 | GitHub: huocai250

检测常见的配置类问题：
  - 点击劫持（缺少 X-Frame-Options / CSP frame-ancestors）
  - 目录列表（Index of /）
  - 调试模式开启（Django/Flask/Werkzeug/Laravel/Symfony 调试页、堆栈跟踪）
  - 详细错误信息泄露（异常堆栈、框架报错、路径泄露）
"""
import re
from core.scanner import BaseScanner
from core.colors import log

DEBUG_SIGNS = [
    (r"Werkzeug Debugger", "Werkzeug/Flask 调试器"),
    (r"Traceback \(most recent call last\)", "Python 堆栈跟踪"),
    (r"DEBUG\s*=\s*True", "调试模式配置"),
    (r"Whoops\\?, looks like something went wrong", "Laravel 调试页"),
    (r"Symfony\\Component", "Symfony 异常"),
    (r"<title>.*(Exception|Error).*</title>", "框架异常页"),
    (r"java\.lang\.[A-Za-z]+Exception", "Java 异常堆栈"),
    (r"org\.springframework", "Spring 异常堆栈"),
    (r"Warning: .* on line \d+", "PHP 警告/路径泄露"),
    (r"Fatal error: .* in .* on line \d+", "PHP 致命错误/路径泄露"),
    (r"ORA-\d{5}", "Oracle 数据库错误"),
    (r"You have an error in your SQL syntax", "MySQL 语法错误"),
    (r"Microsoft OLE DB Provider", "MSSQL 错误"),
]

DIR_LISTING = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /", re.I)


class MisconfigScanner(BaseScanner):
    name = "misconfig"
    passive = True

    def run(self):
        log("INFO", "安全配置错误检测（点击劫持/目录列表/调试/错误信息）...")
        r = self.baseline(self.target)
        if not r:
            return

        self._clickjacking(r)
        self._error_disclosure(r)
        self._dir_listing(r)

    def _clickjacking(self, r):
        headers = {k.lower(): v for k, v in r.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        framed = "frame-ancestors" in csp.lower()
        if not xfo and not framed:
            self.add("点击劫持", "MEDIUM",
                     "缺少 X-Frame-Options 且 CSP 未设置 frame-ancestors，页面可被 iframe 嵌套（点击劫持）",
                     url=self.target)
            log("VULN", "[点击劫持] 页面无 frame 保护")

    def _error_disclosure(self, r):
        body = r.text or ""
        for pattern, desc in DEBUG_SIGNS:
            if re.search(pattern, body, re.I):
                sev = "HIGH" if ("调试" in desc or "Debugger" in desc) else "MEDIUM"
                self.add("信息泄露", sev,
                         f"页面泄露{desc}，可能暴露源码/路径/配置",
                         evidence=desc, url=self.target, confidence="疑似")
                log("VULN", f"[信息泄露] {desc}")
                break  # 一个页面报一次即可

    def _dir_listing(self, r):
        if DIR_LISTING.search(r.text or ""):
            self.add("信息泄露", "MEDIUM",
                     "开启了目录列表（Index of /），可枚举服务器文件",
                     url=self.target)
            log("VULN", "[配置错误] 目录列表开启")
