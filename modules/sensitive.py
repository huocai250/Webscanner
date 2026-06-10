"""
敏感信息泄露检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 文件暴露检测加入软404过滤 + 内容特征验证，消除误报
- 每类文件有专属的内容验证规则
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
from core.scanner import BaseScanner

PATTERNS = {
    "AWS Access Key":      (r'AKIA[0-9A-Z]{16}',                             "CRITICAL"),
    "AWS Secret Key":      (r'(?i)aws[_\-\s]?secret[_\-\s]?key\s*[=:]\s*\S{20,}', "CRITICAL"),
    "Private Key":         (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',  "CRITICAL"),
    "Password in Source":  (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "HIGH"),
    "Database URL":        (r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\'<>]+', "HIGH"),
    "API Key":             (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}', "HIGH"),
    "JWT Token":           (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "HIGH"),
    "Google API Key":      (r'AIza[0-9A-Za-z\-_]{35}',                      "HIGH"),
    "Stripe Secret Key":   (r'sk_live_[0-9a-zA-Z]{24}',                     "CRITICAL"),
    "GitHub Token":        (r'ghp_[0-9A-Za-z]{36}',                         "CRITICAL"),
    "Email Address":       (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', "LOW"),
    "Internal IP":         (r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b', "MEDIUM"),
    "Phone (CN)":          (r'\b1[3-9]\d{9}\b',                             "LOW"),
    "Chinese ID Card":     (r'\b\d{17}[\dXx]\b',                            "HIGH"),
}

# 每个文件的验证规则：(路径, 严重级别, 描述, [内容特征列表])
# 内容特征：至少匹配一个才算真实暴露，避免软404误报
EXPOSED_FILES = [
    (".git/HEAD",
     "CRITICAL", ".git 目录暴露，可导致源码泄露",
     ["ref: refs/", "ref: HEAD"]),

    (".git/config",
     "CRITICAL", ".git/config 暴露，含仓库配置",
     ["[core]", "[remote", "repositoryformatversion"]),

    (".env",
     "CRITICAL", ".env 配置文件暴露，含密钥/数据库凭据",
     ["DB_", "APP_KEY", "SECRET", "PASSWORD", "TOKEN", "API_"]),

    (".env.local",
     "CRITICAL", ".env.local 文件暴露",
     ["DB_", "APP_KEY", "SECRET", "PASSWORD"]),

    ("phpinfo.php",
     "HIGH", "phpinfo 页面暴露，泄露服务器配置",
     ["PHP Version", "phpinfo()", "PHP License", "php.ini"]),

    (".htpasswd",
     "CRITICAL", ".htpasswd 暴露，含加密密码",
     # htpasswd 格式：user:$apr1$... 或 user:{SHA}... 或 user:crypt
     [r":\$apr1\$", r":\{SHA\}", r":(?:[A-Za-z0-9+/]{13}$)"]),

    ("web.config",
     "HIGH", "web.config 暴露，可能含密钥",
     ["<configuration>", "<connectionStrings>", "<?xml"]),

    ("composer.json",
     "LOW", "composer.json 暴露，泄露依赖信息",
     ['"require"', '"name"', '"version"']),

    ("package.json",
     "LOW", "package.json 暴露，泄露依赖信息",
     ['"dependencies"', '"name"', '"version"', '"scripts"']),

    (".DS_Store",
     "LOW", ".DS_Store 暴露，泄露目录结构",
     ["\x00\x00\x00\x01", "Bud1", "\x41\x6c\x6c\x6f"]),   # macOS DS_Store 魔数

    ("wp-config.php.bak",
     "CRITICAL", "WordPress 配置备份文件暴露",
     ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"]),

    ("backup.sql",
     "CRITICAL", "数据库备份文件暴露",
     ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "-- MySQL dump"]),

    ("dump.sql",
     "CRITICAL", "SQL dump 文件暴露",
     ["INSERT INTO", "CREATE TABLE", "DROP TABLE"]),

    (".bash_history",
     "HIGH", ".bash_history 暴露，含命令历史",
     ["sudo ", "ssh ", "mysql ", "wget ", "curl "]),

    ("server-status",
     "MEDIUM", "Apache server-status 暴露",
     ["Apache Server Status", "Server Version", "Scoreboard"]),

    ("actuator/env",
     "HIGH", "Spring Boot Actuator env 暴露",
     ["activeProfiles", "propertySources", "systemProperties"]),

    ("actuator/mappings",
     "HIGH", "Spring Boot Actuator mappings 暴露",
     ["dispatcherServlets", "requestMappingHandlerMapping"]),
]

# 软404特征：命中这些说明页面是自定义404，不是真实文件
SOFT_404_SIGS = [
    "404", "not found", "page not found", "找不到", "页面不存在",
    "does not exist", "no encontrado", "introuvable",
    "error 404", "http 404",
]


class SensitiveInfoScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._soft404_body = ""  # 延迟到 run() 采样，避免构造期异常

    def _get_soft404_body(self) -> str:
        """采样软404参考页面内容"""
        r = self.get(self.build_url("__ws_sensitive_nx_ref_12345__"))
        return r.text if r else ""

    def run(self):
        log.info("敏感信息泄露检测...")
        self._soft404_body = self._get_soft404_body()  # 延迟采样
        self._scan_page()
        self._check_exposed_files()

    def _scan_page(self):
        r = self.get(self.target)
        if not r:
            return
        for name, (pattern, severity) in PATTERNS.items():
            matches = re.findall(pattern, r.text)
            if not matches:
                continue
            sample = str(matches[0])[:60]
            icon = "VULN" if severity in ["CRITICAL", "HIGH"] else "WARN"
            if icon == "VULN":
                log.warning(f"[VULN][敏感信息] {name} ({len(matches)} 处)")
            else:
                log.warning(f"[敏感信息] {name} ({len(matches)} 处)")
            self.result.add("敏感信息泄露", severity,
                            f"源码中发现 {name} ({len(matches)} 处)",
                            sample, url=self.target)

    def _check_exposed_files(self):
        for path, severity, desc, content_sigs in EXPOSED_FILES:
            url = self.build_url(path)
            r   = self.get(url)

            if not r or r.status_code != 200:
                continue

            # ── 软404过滤1：与软404参考页面长度相似 ──
            if self._soft404_body:
                diff = abs(len(r.text) - len(self._soft404_body))
                if diff < 100:
                    continue  # 与随机404响应几乎一样，是软404

            # ── 软404过滤2：响应含通用404特征词 ──
            text_lower = r.text.lower()
            if any(s in text_lower for s in SOFT_404_SIGS) and len(r.text) < 8000:
                continue

            # ── 内容特征验证：必须匹配至少一个才算真实暴露 ──
            verified = False
            for sig in content_sigs:
                try:
                    # 支持正则和普通字符串
                    if re.search(sig, r.text, re.I):
                        verified = True
                        break
                except re.error:
                    # 不是正则，直接字符串匹配
                    if sig in r.text:
                        verified = True
                        break

            if not verified:
                continue   # 内容特征不符，跳过（软404或无关页面）

            log.warning("[VULN] " +  f"[文件暴露] {path} → {desc}")
            self.result.add("文件暴露", severity, desc,
                            r.text[:150], url=url)
