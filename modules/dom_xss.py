"""
DOM XSS 汇聚点静态分析模块（被动）
Author: 火柴 | GitHub: huocai250

在页面与内联/外链 JS 中静态查找「危险汇聚点(sink) + 可控源(source)」的组合
（如 location.hash 流入 innerHTML / document.write / eval）。这是反射型/存储型
XSS 之外的重要面。仅静态分析源码，不执行、不注入。
"""
import re
from urllib.parse import urlparse, urljoin
from core.scanner import BaseScanner
from core.colors import log

# 可控源
SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"document\.URL",
    r"document\.documentURI", r"document\.referrer", r"window\.name",
    r"location\.pathname", r"postMessage",
]
# 危险汇聚点
SINKS = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write(ln)?\s*\(", "document.write"),
    (r"\beval\s*\(", "eval"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"new\s+Function\s*\(", "Function()"),
    (r"\.setAttribute\s*\(\s*['\"]on", "on* 事件属性"),
    (r"\$\(.*\)\.html\s*\(", "jQuery.html()"),
    (r"\.src\s*=\s*", "src 赋值"),
]
MAX_JS = 25


class DOMXSSScanner(BaseScanner):
    name = "domxss"
    passive = True

    def run(self):
        log("INFO", "DOM XSS 汇聚点静态分析...")
        r = self.baseline(self.target)
        if not r or not r.text:
            return
        docs = [(self.target, r.text)]
        for jm in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I):
            ju = urljoin(r.url, jm.group(1))
            if urlparse(ju).netloc == urlparse(self.target).netloc:
                jr = self.get(ju)
                if jr and jr.text:
                    docs.append((ju, jr.text))
            if len(docs) >= MAX_JS:
                break
        for url, code in docs:
            self._analyze(url, code)

    def _analyze(self, url, code):
        has_source = [s for s in SOURCES if re.search(s, code)]
        if not has_source:
            return
        hit_sinks = [label for pat, label in SINKS if re.search(pat, code)]
        if not hit_sinks:
            return
        # 源与汇聚点同时出现 => 提示潜在 DOM XSS（需人工确认数据流）
        sev = "MEDIUM" if any(s in ("innerHTML", "document.write", "eval",
                                     "Function()", "insertAdjacentHTML")
                              for s in hit_sinks) else "LOW"
        log("VULN", f"[DOM XSS] {url} sink={hit_sinks[:3]}")
        self.add("XSS", sev,
                 f"DOM XSS 面：脚本同时存在可控源({', '.join(has_source[:3])})与"
                 f"危险汇聚点({', '.join(hit_sinks[:3])})，需人工确认数据流是否可达",
                 evidence=f"sinks={hit_sinks[:4]} @ {url}", url=url, confidence="疑似")
