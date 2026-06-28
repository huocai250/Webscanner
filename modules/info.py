"""
信息收集模块
Author: 火柴 | GitHub: huocai250
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
import socket
from urllib.parse import urlparse
from core.scanner import BaseScanner


class InfoGatherer(BaseScanner):
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
        _before = self.result.total()
        log.info( "开始信息收集...")
        self._server_info()
        self._tech_detect()
        self._robots_txt()
        self._sitemap()
        self._dns_info()
        self._check_waf()
        self._log_module_done("信息收集", _before)

    def _server_info(self):
        r = self.get(self.target)
        if not r:
            return
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                        "X-Generator", "Via", "X-Runtime"]
        for h in info_headers:
            if h in r.headers:
                log.info( f"Header [{h}]: {r.headers[h]}")
                self.result.add("信息收集", "INFO",
                                f"响应头暴露: {h} = {r.headers[h]}", url=self.target)

    def _tech_detect(self):
        r = self.get(self.target)
        if not r:
            return
        content = (r.text + str(r.headers)).lower()
        detected = []
        for tech, sigs in self.TECH_SIGNATURES.items():
            if any(s.lower() in content for s in sigs):
                detected.append(tech)
        if detected:
            log.info( f"技术栈识别: {', '.join(detected)}")
            self.result.add("技术栈", "INFO", f"检测到: {', '.join(detected)}", url=self.target)

    def _robots_txt(self):
        url = self.build_url("/robots.txt")
        r = self.get(url)
        if r and r.status_code == 200:
            log.info( f"发现 robots.txt")
            self.result.add("信息收集", "INFO", "robots.txt 存在", r.text[:300], url)
            paths = re.findall(r"Disallow:\s*(/[^\s]*)", r.text)
            for p in paths:
                log.info( f"  robots.txt Disallow: {p}")

    def _sitemap(self):
        for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"]:
            r = self.get(self.build_url(path))
            if r and r.status_code == 200:
                log.info( f"发现 {path}")
                self.result.add("信息收集", "INFO", f"Sitemap 存在: {path}", url=self.build_url(path))

    def _dns_info(self):
        hostname = urlparse(self.target).hostname
        try:
            ip = socket.gethostbyname(hostname)
            log.info( f"目标 IP: {ip}")
            self.result.add("信息收集", "INFO", f"域名解析 IP: {ip}")
            # 反向解析
            try:
                rdns = socket.gethostbyaddr(ip)[0]
                if rdns != hostname:
                    log.info( f"反向 DNS: {rdns}")
                    self.result.add("信息收集", "INFO", f"反向 DNS: {rdns}")
            except Exception as e:
                log.debug(f"反向 DNS 查询失败: {e}")
        except Exception as e:
            log.debug(f"DNS 查询失败: {e}")

    def _check_waf(self):
        """简单 WAF 指纹识别"""
        r = self.get(self.target, params={"id": "1'<script>alert(1)</script>"})
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
                log.warning( f"检测到 WAF: {waf}，可能影响漏洞测试准确性")
                self.result.add("WAF 检测", "INFO", f"发现 WAF: {waf}")
                return
