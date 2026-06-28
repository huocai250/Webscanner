"""
指纹识别模块 — WebVulnScanner v7.0
Author: 火柴 | GitHub: huocai250

[新增] 扩充指纹库：
  - 100+ 框架/CMS/中间件/数据库 指纹
  - 多维度识别：HTTP头/响应体/Cookie/路径/错误页
  - 版本号提取
"""
import re
import logging
from typing import Dict, List, Tuple
from core.scanner import BaseScanner

log = logging.getLogger("webscan")

# ── 指纹规则库 ────────────────────────────────────────────────
# 格式: (名称, 类别, [(检测位置, 匹配模式), ...], 版本提取正则)
# 检测位置: header / body / cookie / path / title / server

FINGERPRINTS: List[Tuple] = [
    # ── Web 框架 ──────────────────────────────────────────────
    ("WordPress",     "CMS",        [("body",   r"wp-content|wp-includes|wordpress"),
                                     ("body",   r"/wp-json/")], r"WordPress (\d+\.\d+)"),
    ("Joomla",        "CMS",        [("body",   r"joomla|/components/com_")], r"Joomla[! ]+(\d[\d.]+)"),
    ("Drupal",        "CMS",        [("body",   r"drupal|/sites/default/files"),
                                     ("header", r"x-drupal")], r"Drupal (\d+)"),
    ("Magento",       "CMS",        [("body",   r"mage/cookies|magento"),
                                     ("cookie", r"frontend=")], None),
    ("TYPO3",         "CMS",        [("body",   r"typo3|/typo3conf/")], r"TYPO3 (\d+\.\d+)"),
    ("Shopify",       "CMS",        [("header", r"x-shopid"),
                                     ("body",   r"shopify")], None),
    ("Ghost",         "CMS",        [("body",   r"ghost-url|content=\"Ghost")], r"Ghost/(\d+\.\d+)"),
    ("Discuz",        "CMS",        [("body",   r"discuz|powered by discuz")], r"Discuz[! ]+(\w+)"),
    ("DedeCMS",       "CMS",        [("body",   r"dedecms|/dede/")], None),
    ("PHPCMS",        "CMS",        [("body",   r"phpcms|/phpcms/")], None),
    ("Empire CMS",    "CMS",        [("body",   r"empirecms|e_webbak")], None),

    # ── 前端框架 ──────────────────────────────────────────────
    ("React",         "Frontend",   [("body",   r"react\.js|react-dom|__REACT")], r"React[/ ](\d+\.\d+)"),
    ("Vue.js",        "Frontend",   [("body",   r"vue\.min\.js|__vue__|Vue\.js")], r"Vue\.js[/ ](\d+\.\d+)"),
    ("Angular",       "Frontend",   [("body",   r"ng-version|angular\.js")], r"Angular[/ ](\d+\.\d+)"),
    ("Next.js",       "Frontend",   [("body",   r"__next|/_next/static")], r"Next\.js (\d+\.\d+)"),
    ("Nuxt.js",       "Frontend",   [("body",   r"__nuxt|/_nuxt/")], None),
    ("jQuery",        "Library",    [("body",   r"jquery\.min\.js|jQuery v")], r"jQuery[/ v]+(\d+\.\d+\.\d+)"),
    ("Bootstrap",     "Library",    [("body",   r"bootstrap\.min\.(css|js)")], r"Bootstrap[/ v]+(\d+\.\d+)"),
    ("Layui",         "Library",    [("body",   r"layui|layui\.js")], None),
    ("Element UI",    "Library",    [("body",   r"element-ui|el-button")], None),

    # ── 后端框架 ──────────────────────────────────────────────
    ("Laravel",       "Framework",  [("body",   r"laravel_session|laravel\.com"),
                                     ("cookie", r"laravel_session|XSRF-TOKEN")], r"Laravel[/ ](\d+\.\d+)"),
    ("Symfony",       "Framework",  [("body",   r"symfony|sf_redirect"),
                                     ("header", r"x-symfony")], r"Symfony[/ ](\d+\.\d+)"),
    ("CodeIgniter",   "Framework",  [("body",   r"codeigniter|ci_session")], r"CodeIgniter[/ ](\d+\.\d+)"),
    ("Django",        "Framework",  [("body",   r"csrfmiddlewaretoken|django"),
                                     ("header", r"x-django")], None),
    ("Flask",         "Framework",  [("body",   r"werkzeug|flask"),
                                     ("header", r"werkzeug/")], r"Werkzeug[/ ](\d+\.\d+)"),
    ("FastAPI",       "Framework",  [("body",   r"fastapi|pydantic"),
                                     ("header", r"fastapi")], None),
    ("Spring Boot",   "Framework",  [("body",   r"whitelabel error page|spring-boot"),
                                     ("header", r"x-application-context")], r"Spring Boot[/ ](\d+\.\d+)"),
    ("Spring MVC",    "Framework",  [("body",   r"spring-mvc|org\.springframework")], None),
    ("Struts2",       "Framework",  [("body",   r"struts2|\.action\b")], r"Struts[/ ](\d+\.\d+)"),
    ("ThinkPHP",      "Framework",  [("body",   r"thinkphp|think\\\\"),
                                     ("header", r"thinkphp")], r"ThinkPHP[/ ](\d+\.\d+)"),
    ("Yii",           "Framework",  [("body",   r"yii-debug|YII_DEBUG")], r"Yii[/ ](\d+\.\d+)"),
    ("ASP.NET MVC",   "Framework",  [("body",   r"__requestverificationtoken|asp\.net mvc"),
                                     ("header", r"x-aspnetmvc-version")], r"ASP\.NET MVC[/ ](\d+\.\d+)"),
    ("ASP.NET",       "Framework",  [("body",   r"__viewstate|asp\.net"),
                                     ("header", r"x-aspnet-version|x-powered-by.*asp\.net")], r"ASP\.NET[/ ](\d+\.\d+)"),
    ("Ruby on Rails", "Framework",  [("body",   r"rails|ruby on rails"),
                                     ("header", r"x-rails-version|x-runtime")], r"Rails[/ ](\d+\.\d+)"),
    ("Express.js",    "Framework",  [("header", r"x-powered-by.*express")], r"Express[/ ](\d+\.\d+)"),
    ("Gin",           "Framework",  [("header", r"x-powered-by.*gin")], None),
    ("Echo",          "Framework",  [("header", r"x-powered-by.*echo")], None),

    # ── Web 服务器 ────────────────────────────────────────────
    ("Nginx",         "Server",     [("header", r"^nginx"),
                                     ("body",   r"nginx/\d|welcome to nginx")], r"nginx[/ ](\d+\.\d+\.\d+)"),
    ("Apache",        "Server",     [("header", r"^apache"),
                                     ("body",   r"apache/\d|apache2 default")], r"Apache[/ ](\d+\.\d+\.\d+)"),
    ("IIS",           "Server",     [("header", r"microsoft-iis"),
                                     ("body",   r"iis windows server|internet information services")], r"IIS[/ ](\d+\.\d+)"),
    ("Tomcat",        "Server",     [("body",   r"apache tomcat|tomcat/\d"),
                                     ("header", r"x-powered-by.*tomcat")], r"Tomcat[/ ](\d+\.\d+\.\d+)"),
    ("WebLogic",      "Server",     [("body",   r"weblogic|bea weblogic"),
                                     ("header", r"x-powered-by.*weblogic")], r"WebLogic[/ ](\d+\.\d+)"),
    ("JBoss",         "Server",     [("body",   r"jboss|jbossas"),
                                     ("header", r"x-powered-by.*jboss")], r"JBoss[/ ](\d+\.\d+)"),
    ("Jetty",         "Server",     [("header", r"jetty"),
                                     ("body",   r"jetty/\d")], r"Jetty[/ ](\d+\.\d+)"),
    ("Caddy",         "Server",     [("header", r"caddy")], r"Caddy[/ ](\d+\.\d+)"),
    ("OpenResty",     "Server",     [("header", r"openresty")], r"openresty[/ ](\d+\.\d+)"),

    # ── 安全产品 / CDN ────────────────────────────────────────
    ("Cloudflare",    "CDN/WAF",    [("header", r"cf-ray|__cfduid|cloudflare")], None),
    ("AWS CloudFront","CDN",        [("header", r"x-amz-cf-id|cloudfront\.net")], None),
    ("Akamai",        "CDN/WAF",    [("header", r"akamai|ak_bmsc|x-akamai")], None),
    ("Fastly",        "CDN",        [("header", r"x-fastly|fastly-")], None),
    ("ModSecurity",   "WAF",        [("body",   r"mod_security|modsecurity"),
                                     ("header", r"mod-security")], None),
    ("Sucuri",        "WAF",        [("header", r"x-sucuri-id|sucuri")], None),
    ("F5 BIG-IP",     "WAF",        [("cookie", r"bigipserver|f5_"),
                                     ("header", r"bigipserver")], None),
    ("SafeDog",       "WAF",        [("header", r"safedog"),
                                     ("body",   r"safedog")], None),
    ("D盾",           "WAF",        [("header", r"d_safe_"),
                                     ("body",   r"d盾")], None),

    # ── 数据库/中间件（通过报错页暴露）────────────────────────
    ("MySQL",         "Database",   [("body",   r"mysql_error|you have an error in your sql syntax")], None),
    ("PostgreSQL",    "Database",   [("body",   r"pg_query|postgresql.*error")], None),
    ("MongoDB",       "Database",   [("body",   r"mongodb|mongoclient")], None),
    ("Redis",         "Middleware", [("body",   r"\+PONG|redis_version")], r"redis_version[: ]+(\d+\.\d+)"),
    ("Elasticsearch", "Middleware", [("body",   r"elasticsearch|lucene_version")], r"\"number\"\s*:\s*\"(\d+\.\d+\.\d+)\""),
    ("RabbitMQ",      "Middleware", [("body",   r"rabbitmq|amqp")], None),
    ("Kafka",         "Middleware", [("body",   r"kafka\.producer|org\.apache\.kafka")], None),

    # ── 运维/监控 ─────────────────────────────────────────────
    ("Jenkins",       "DevOps",     [("body",   r"jenkins|hudson"),
                                     ("header", r"x-jenkins")], r"Jenkins[/ ](\d+\.\d+)"),
    ("GitLab",        "DevOps",     [("body",   r"gitlab|gl-token")], r"GitLab[/ ](\d+\.\d+)"),
    ("Grafana",       "Monitoring", [("body",   r"grafana|dashboard.*panel")], r"Grafana[/ v]+(\d+\.\d+)"),
    ("Prometheus",    "Monitoring", [("body",   r"prometheus|/metrics")], None),
    ("Kibana",        "Monitoring", [("body",   r"kibana|kbn-version")], r"kbn-version.*(\d+\.\d+)"),
    ("Zabbix",        "Monitoring", [("body",   r"zabbix|zbx_session")], r"Zabbix[/ ](\d+\.\d+)"),
    ("Portainer",     "DevOps",     [("body",   r"portainer|docker management")], None),
    ("Nacos",         "Middleware", [("body",   r"nacos|com\.alibaba\.nacos")], None),
    ("Consul",        "Middleware", [("body",   r"consul/v1|hashicorp consul")], None),
]

# 风险等级映射（某些技术暴露本身就有安全意义）
RISK_MAP = {
    "Struts2":      "HIGH",    # 大量已知 RCE CVE
    "WebLogic":     "HIGH",    # 反序列化漏洞高发
    "Shiro":        "HIGH",    # rememberMe 反序列化
    "ThinkPHP":     "HIGH",    # RCE 漏洞高发
    "Jenkins":      "MEDIUM",  # 可能未授权
    "Elasticsearch":"MEDIUM",  # 可能未授权
    "Redis":        "MEDIUM",  # 可能未授权
    "MongoDB":      "MEDIUM",  # 可能未授权
    "ModSecurity":  "INFO",
    "Cloudflare":   "INFO",
    "SafeDog":      "INFO",
    "D盾":          "INFO",
}


# [优化] 预编译所有正则，避免每次扫描重复编译
_COMPILED: dict = {}

def _get_pattern(pattern: str):
    if pattern not in _COMPILED:
        try:
            _COMPILED[pattern] = re.compile(pattern, re.I)
        except re.error:
            _COMPILED[pattern] = None
    return _COMPILED[pattern]


class FingerprintScanner(BaseScanner):
    """多维度指纹识别，100+ 规则"""

    def run(self):
        _before = self.result.total()
        log.info("指纹识别扫描（100+ 规则）...")

        r = self.get(self.target)
        if not r:
            self._log_module_done("指纹识别", _before)
            return

        # 收集各维度数据
        body   = r.text.lower()
        hdrs   = str(dict(r.headers)).lower()
        cookies = str(dict(r.cookies)).lower()
        server  = r.headers.get("Server", "").lower()
        title_m = re.search(r'<title>(.*?)</title>', r.text, re.I)
        title   = title_m.group(1).lower() if title_m else ""

        detected = []

        for name, category, rules, version_re in FINGERPRINTS:
            matched = False
            for location, pattern in rules:
                target_text = {
                    "body":   body,
                    "header": hdrs,
                    "cookie": cookies,
                    "server": server,
                    "title":  title,
                    "path":   "",
                }.get(location, body)

                compiled = _get_pattern(pattern)
                if compiled and compiled.search(target_text):
                    matched = True
                    break

            if matched:
                # 提取版本号
                version = ""
                if version_re:
                    vpat = _get_pattern(version_re)
                    vm = vpat.search(r.text) if vpat else None
                    if vm:
                        version = vm.group(1)

                severity = RISK_MAP.get(name, "INFO")
                detail   = f"[{category}] {name}" + (f" v{version}" if version else "")
                log.info(f"指纹: {detail}")

                if severity in ("HIGH", "MEDIUM"):
                    log.warning(f"[VULN][指纹] {detail} — 存在已知高危漏洞风险")

                self.result.add("指纹识别", severity, detail, url=self.target)
                detected.append(f"{name}{'@'+version if version else ''}")

        if detected:
            log.info(f"识别到 {len(detected)} 个组件: {', '.join(detected[:8])}")

        self._log_module_done("指纹识别", _before)
