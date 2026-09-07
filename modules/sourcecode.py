"""
源码泄露 / 调试端点检测模块（主动）
Author: 火柴 | GitHub: huocai250
"""
from core.scanner import BaseScanner
from core.colors import log

# 源码文件被当作静态文件返回（未被解释器执行）—— 语言特征签名
SOURCE_CHECKS = [
    ("index.php.txt", ["<?php"], "PHP"),
    ("index.jsp.txt", ["<%", "out.println"], "JSP"),
    ("Main.java", ["public class", "import java"], "Java"),
    ("app.py.txt", ["import ", "def ", "Flask"], "Python"),
    ("app.rb.txt", ["require ", "def ", "end"], "Ruby"),
    ("Program.cs", ["using System", "namespace "], "C#"),
    ("main.go.txt", ["package main", "func "], "Go"),
]


class SourceDisclosureScanner(BaseScanner):
    name = "sourcecode"
    passive = True

    def run(self):
        log("INFO", "源码泄露检测...")
        # 1) 首页是否直接暴露 PHP 源码（解释器未执行）
        r = self.baseline(self.target)
        if r and "<?php" in (r.text or "")[:2000]:
            self.add("敏感信息泄露", "HIGH",
                     "页面直接输出 PHP 源码（解释器未执行），源码泄露",
                     url=self.target, confidence="疑似")
            log("VULN", "[源码泄露] 首页输出 PHP 源码")
        # 2) 常见源码文件探测
        self.map(self._check, SOURCE_CHECKS)

    def _check(self, entry):
        path, signs, lang = entry
        r = self.get(self.url("/" + path))
        if r and r.status_code == 200 and any(s in (r.text or "") for s in signs):
            log("VULN", f"[源码泄露] {lang}: /{path}")
            self.add("敏感信息泄露", "MEDIUM",
                     f"{lang} 源码文件可直接下载: /{path}",
                     evidence=f"HTTP 200 @ /{path}", url=r.url, confidence="疑似")
            return path
        return None


class DebugEndpointScanner(BaseScanner):
    name = "debugendp"
    passive = True

    ENDPOINTS = [
        ("/debug", ["debug", "Whoops", "Traceback"], "MEDIUM"),
        ("/__debug__/", ["Werkzeug", "console", "traceback"], "HIGH"),
        ("/debug/vars", ["cmdline", "memstats"], "MEDIUM"),  # Go expvar
        ("/debug/pprof/", ["Types of profiles", "pprof"], "HIGH"),  # Go pprof
        ("/_debugbar/open", ["PHPDebugbar", "debugbar"], "MEDIUM"),
        ("/rails/info/properties", ["Rails version", "Ruby version"], "MEDIUM"),
        ("/rails/info/routes", ["Helper", "HTTP Verb"], "MEDIUM"),
        ("/__clockwork/app", ["clockwork"], "MEDIUM"),
        ("/actuator/shutdown", [], "CRITICAL"),  # 存在即危险（POST 才生效，这里仅探测）
    ]

    def run(self):
        log("INFO", "调试端点检测...")
        self.map(self._check, self.ENDPOINTS)

    def _check(self, entry):
        path, signs, sev = entry
        r = self.get(self.url(path))
        if not r or r.status_code not in (200, 405):
            return None
        body = r.text or ""
        if signs:
            if not any(s in body for s in signs):
                return None
        else:
            # 无签名项（如 /actuator/shutdown）：200 或 405 都视为端点存在
            if r.status_code not in (200, 405):
                return None
        log("VULN", f"[调试端点] {path}")
        self.add("配置错误", sev,
                 f"调试/诊断端点暴露: {path}（可能泄露内部信息或提供危险操作）",
                 evidence=f"HTTP {r.status_code} @ {path}", url=r.url, confidence="疑似")
        return path
