"""
CMS / 框架专项检测模块（被动 / 仅检测暴露面）
Author: 火柴 | GitHub: huocai250

针对常见 CMS/框架检测**已暴露的敏感端点或信息**并给出加固建议：
  - WordPress: /wp-json 用户枚举、xmlrpc.php、readme.html 版本泄露
  - Joomla:    /administrator、configuration.php~ 备份
  - ThinkPHP:  版本信息页、调试入口
  - Spring Boot Actuator: /actuator、/actuator/env、/actuator/health 暴露
  - Apache Shiro: rememberMe Cookie（存在反序列化历史 CVE 的指示）

本模块只**检测端点是否暴露**，不利用任何反序列化/RCE 漏洞。
"""
from core.scanner import BaseScanner
from core.colors import log


class CMSScanner(BaseScanner):
    name = "cms"
    passive = True

    def run(self):
        log("INFO", "CMS/框架专项检测（暴露面）...")
        tech = self.ctx.tech_names()

        # 即使指纹未命中，也做少量通用暴露检测
        self._actuator()
        self._shiro()

        if "wordpress" in tech:
            self._wordpress()
        if "joomla" in tech:
            self._joomla()
        if "thinkphp" in tech:
            self._thinkphp()

        # 指纹没识别出 CMS 时，做一次轻量 WordPress 探测（很常见）
        if not tech & {"wordpress", "joomla", "drupal"}:
            self._wordpress(light=True)

    # ---------- 各 CMS ----------
    def _wordpress(self, light=False):
        # 用户枚举端点
        r = self.get(self.url("/wp-json/wp/v2/users"))
        if r and r.status_code == 200 and '"slug"' in (r.text or ""):
            self.add("敏感信息泄露", "MEDIUM",
                     "WordPress REST API 用户枚举端点开放 (/wp-json/wp/v2/users)",
                     evidence=r.text[:120], url=r.url)
            log("VULN", "[WordPress] 用户枚举端点开放")
        # xmlrpc
        x = self.get(self.url("/xmlrpc.php"))
        if x and x.status_code in (200, 405) and "XML-RPC" in (x.text or ""):
            self.add("配置错误", "LOW",
                     "WordPress xmlrpc.php 可访问（可能被用于暴力破解/放大攻击）",
                     url=x.url, confidence="疑似")
        if light:
            return
        # readme 版本
        rd = self.get(self.url("/readme.html"))
        if rd and rd.status_code == 200 and "WordPress" in (rd.text or ""):
            self.add("信息泄露", "LOW",
                     "WordPress readme.html 可访问，可能泄露版本号",
                     url=rd.url, confidence="疑似")

    def _joomla(self):
        for path, sev, desc in [
            ("/administrator/", "INFO", "Joomla 后台入口可访问"),
            ("/configuration.php~", "HIGH", "Joomla 配置文件备份泄露 (configuration.php~)"),
            ("/administrator/manifests/files/joomla.xml", "LOW",
             "Joomla 版本清单可访问，泄露版本号"),
        ]:
            r = self.get(self.url(path))
            if r and r.status_code == 200 and r.text:
                self.add("敏感信息泄露" if sev == "HIGH" else "信息泄露", sev,
                         desc, url=r.url, confidence="疑似")
                log("VULN", f"[Joomla] {desc}")

    def _thinkphp(self):
        # ThinkPHP 版本泄露（不触发任何 RCE payload）
        r = self.get(self.url("/"))
        if r and "ThinkPHP" in (r.text or "") + str(r.headers):
            self.add("信息泄露", "LOW",
                     "检测到 ThinkPHP，建议确认已关闭调试模式并升级到安全版本",
                     url=self.target, confidence="信息")

    # ---------- 通用（框架级）----------
    def _actuator(self):
        base_hits = []
        for path in ["/actuator", "/actuator/health", "/actuator/env",
                     "/actuator/beans", "/env", "/health"]:
            r = self.get(self.url(path))
            if not r or r.status_code != 200 or not r.text:
                continue
            txt = r.text
            if any(k in txt for k in ('"status"', '"_links"', '"propertySources"',
                                      '"activeProfiles"', '"beans"')):
                base_hits.append(path)
                sev = "HIGH" if path in ("/actuator/env", "/env",
                                         "/actuator/beans") else "MEDIUM"
                self.add("敏感信息泄露", sev,
                         f"Spring Boot Actuator 端点暴露: {path}"
                         + ("（/env 可能泄露配置与凭据）" if "env" in path else ""),
                         evidence=txt[:120], url=r.url)
                log("VULN", f"[Actuator] 暴露端点: {path}")

    def _shiro(self):
        # 发送一个带 rememberMe 的请求，若响应 Set-Cookie 回显 rememberMe=deleteMe
        # 则强指示使用了 Apache Shiro（历史存在反序列化 CVE，仅提示加固）
        r = self.get(self.target, cookies={"rememberMe": "test"})
        if not r:
            return
        setc = " ".join(v for k, v in r.headers.items()
                        if k.lower() == "set-cookie")
        if "rememberMe=deleteMe" in setc or "rememberme=deleteme" in setc.lower():
            self.add("信息泄露", "MEDIUM",
                     "检测到 Apache Shiro（rememberMe 回显 deleteMe）；"
                     "历史版本存在反序列化 RCE (Shiro-550/721)，请确认已升级并更换默认密钥",
                     url=self.target, confidence="疑似")
            log("VULN", "[Shiro] 检测到 Shiro rememberMe 特征")
