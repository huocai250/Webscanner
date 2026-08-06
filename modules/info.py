"""
信息收集模块
Author: 火柴 | GitHub: huocai250
v4.0: 使用基线缓存，避免重复抓取首页
"""
import re
import socket
from urllib.parse import urlparse
from core.scanner import BaseScanner
from core.colors import log


class InfoGatherer(BaseScanner):
    name = "info"
    passive = True

    TECH_SIGNATURES = {
        "WordPress":    ["wp-content", "wp-includes", "wp-json"],
        "Joomla":       ["joomla!", "/components/com_"],
        "Drupal":       ["drupal.settings", "/sites/default/"],
        "Laravel":      ["laravel_session", "xsrf-token"],
        "Django":       ["csrfmiddlewaretoken"],
        "Flask":        ["werkzeug", "flask"],
        "Spring Boot":  ["whitelabel error page", "spring"],
        "ASP.NET":      ["__viewstate", "asp.net_sessionid"],
        "PHP":          ["phpsessid"],
        "jQuery":       ["jquery.min.js"],
        "Bootstrap":    ["bootstrap.min.css"],
        "React":        ["react.js", "react-dom", "__react"],
        "Vue.js":       ["vue.min.js", "__vue__"],
        "Angular":      ["ng-version", "angular.js"],
        "Next.js":      ["__next", "_next/static"],
        "Nuxt.js":      ["__nuxt", "_nuxt/"],
        "Nginx":        ["nginx"],
        "Apache":       ["apache"],
        "Tomcat":       ["apache tomcat"],
        "IIS":          ["iis", "microsoft-iis"],
    }

    def run(self):
        log("INFO", "开始信息收集...")
        base = self.baseline()
        self._server_info(base)
        self._tech_detect(base)
        self._robots_txt()
        self._sitemap()
        self._dns_info()
        self._check_waf()

    def _server_info(self, r):
        if not r:
            return
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                        "X-Generator", "Via", "X-Runtime"]
        for h in info_headers:
            if h in r.headers:
                log("OK", f"Header [{h}]: {r.headers[h]}")
                self.add("信息收集", "INFO",
                         f"响应头暴露: {h} = {r.headers[h]}", url=self.target,
                         confidence="信息")

    def _tech_detect(self, r):
        if not r:
            return
        content = (r.text + str(r.headers)).lower()
        detected = [t for t, sigs in self.TECH_SIGNATURES.items()
                    if any(s.lower() in content for s in sigs)]
        if detected:
            log("OK", f"技术栈识别: {', '.join(detected)}")
            self.add("技术栈", "INFO", f"检测到: {', '.join(detected)}",
                     url=self.target, confidence="信息")

    def _robots_txt(self):
        url = self.url("/robots.txt")
        r = self.get(url)
        if r and r.status_code == 200:
            log("OK", "发现 robots.txt")
            self.add("信息收集", "INFO", "robots.txt 存在", r.text[:300], url,
                     confidence="信息")
            for p in re.findall(r"Disallow:\s*(/[^\s]*)", r.text):
                log("INFO", f"  robots.txt Disallow: {p}")

    def _sitemap(self):
        for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"]:
            r = self.get(self.url(path))
            if r and r.status_code == 200:
                log("OK", f"发现 {path}")
                self.add("信息收集", "INFO", f"Sitemap 存在: {path}",
                         url=self.url(path), confidence="信息")

    def _dns_info(self):
        hostname = urlparse(self.target).hostname
        try:
            ip = socket.gethostbyname(hostname)
            log("OK", f"目标 IP: {ip}")
            self.add("信息收集", "INFO", f"域名解析 IP: {ip}", confidence="信息")
            try:
                rdns = socket.gethostbyaddr(ip)[0]
                if rdns != hostname:
                    log("INFO", f"反向 DNS: {rdns}")
                    self.add("信息收集", "INFO", f"反向 DNS: {rdns}", confidence="信息")
            except Exception:
                pass
        except Exception:
            pass

    def _check_waf(self):
        """简单 WAF 指纹识别。"""
        r = self.get(self.target + "/?id=1%27%3Cscript%3E")
        if not r:
            return
        waf_sigs = {
            "Cloudflare":  ["cloudflare", "__cfduid", "cf-ray"],
            "AWS WAF":     ["awswaf", "x-amzn-requestid"],
            "Akamai":      ["akamai", "ak_bmsc"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri":      ["sucuri", "x-sucuri-id"],
            "F5 BIG-IP":   ["bigipserver", "f5-"],
        }
        content = (r.text + str(dict(r.headers))).lower()
        for waf, sigs in waf_sigs.items():
            if any(s in content for s in sigs):
                log("WARN", f"检测到 WAF: {waf}，可能影响漏洞测试准确性")
                self.add("WAF 检测", "INFO", f"发现 WAF: {waf}", confidence="信息")
                return
