"""
robots / sitemap / well-known 情报模块（被动）
Author: 火柴 | GitHub: huocai250

从 robots.txt、sitemap.xml、/.well-known/ 及跨域策略文件中收集信息与线索：
  - robots.txt 的 Disallow 常「此地无银」地暴露敏感路径
  - sitemap.xml 暴露站点结构
  - crossdomain.xml / clientaccesspolicy.xml 过于宽松（Flash/Silverlight 跨域）
仅收集与提示，不做利用。
"""
import re
from core.scanner import BaseScanner
from core.colors import log


class WellKnownScanner(BaseScanner):
    name = "wellknown"
    passive = True

    def run(self):
        log("INFO", "robots/sitemap/well-known 情报收集...")
        self._robots()
        self._sitemap()
        self._crossdomain()
        self._security_txt()

    def _robots(self):
        r = self.get(self.url("/robots.txt"))
        if not r or r.status_code != 200 or "Disallow" not in (r.text or ""):
            return
        disallow = re.findall(r'(?i)Disallow:\s*(\S+)', r.text)
        interesting = [d for d in disallow
                       if any(k in d.lower() for k in
                              ("admin", "backup", "config", "private", "secret",
                               "api", "internal", "test", "dev", "old", "db",
                               "log", "upload", ".git", "panel", "manage"))]
        if interesting:
            self.add("信息泄露", "LOW",
                     f"robots.txt 的 Disallow 暴露了 {len(interesting)} 个敏感路径线索",
                     evidence=", ".join(interesting[:10]), url=r.url,
                     confidence="信息")
            log("VULN", f"[robots] {len(interesting)} 个敏感路径线索")

    def _sitemap(self):
        for p in ("/sitemap.xml", "/sitemap_index.xml"):
            r = self.get(self.url(p))
            if r and r.status_code == 200 and "<url" in (r.text or "") + (r.text or ""):
                urls = len(re.findall(r'<loc>', r.text))
                self.add("信息泄露", "INFO",
                         f"sitemap 暴露站点结构（约 {urls} 个 URL）",
                         url=r.url, confidence="信息")
                return

    def _crossdomain(self):
        for p in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
            r = self.get(self.url(p))
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if re.search(r'domain=["\']\*["\']', body) or 'uri="*"' in body:
                self.add("CORS", "MEDIUM",
                         f"{p} 配置过于宽松（允许任意域），可导致跨域数据窃取",
                         evidence=body[:120], url=r.url)
                log("VULN", f"[跨域策略] {p} 通配符")

    def _security_txt(self):
        for p in ("/.well-known/security.txt", "/security.txt"):
            r = self.get(self.url(p))
            if r and r.status_code == 200 and "Contact" in (r.text or ""):
                self.add("信息泄露", "INFO",
                         "存在 security.txt（安全联系方式，属良好实践）",
                         url=r.url, confidence="信息")
                return
