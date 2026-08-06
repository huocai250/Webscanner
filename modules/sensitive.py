"""
敏感信息泄露检测模块
Author: 火柴 | GitHub: huocai250
v4.0: 暴露文件检测并发化，使用基线缓存
"""
import re
from core.scanner import BaseScanner
from core.colors import log

PATTERNS = {
    "AWS Access Key":      (r'AKIA[0-9A-Z]{16}',                            "CRITICAL"),
    "AWS Secret Key":      (r'(?i)aws[_\-\s]?secret[_\-\s]?key\s*[=:]\s*\S{20,}', "CRITICAL"),
    "Private Key":         (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',  "CRITICAL"),
    "Password in Source":  (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "HIGH"),
    "Database URL":        (r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\'<>]+', "HIGH"),
    "API Key":             (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}', "HIGH"),
    "JWT Token":           (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "HIGH"),
    "Google API Key":      (r'AIza[0-9A-Za-z\-_]{35}',                     "HIGH"),
    "Stripe Key":          (r'sk_live_[0-9a-zA-Z]{24}',                    "CRITICAL"),
    "GitHub Token":        (r'ghp_[0-9A-Za-z]{36}',                        "CRITICAL"),
    "Slack Token":         (r'xox[baprs]-[0-9A-Za-z\-]{10,}',              "CRITICAL"),
    "Email Address":       (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', "LOW"),
    "Internal IP":         (r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b', "MEDIUM"),
    "Phone (CN)":          (r'\b1[3-9]\d{9}\b',                            "LOW"),
    "Chinese ID Card":     (r'\b\d{17}[\dXx]\b',                           "HIGH"),
    "Credit Card":         (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "CRITICAL"),
}

EXPOSED_FILES = [
    (".git/HEAD",          "CRITICAL", ".git 目录暴露，可能导致源码泄露"),
    (".git/config",        "CRITICAL", ".git/config 暴露，包含仓库配置"),
    (".env",               "CRITICAL", ".env 配置文件暴露，含密钥/数据库凭据"),
    (".env.local",         "CRITICAL", ".env.local 文件暴露"),
    ("composer.json",      "LOW",      "composer.json 暴露，泄露依赖信息"),
    ("package.json",       "LOW",      "package.json 暴露，泄露依赖信息"),
    (".DS_Store",          "LOW",      ".DS_Store 暴露，泄露目录结构"),
    ("phpinfo.php",        "HIGH",     "phpinfo 页面暴露，泄露服务器配置"),
    ("web.config",         "HIGH",     "web.config 暴露，可能含密钥"),
    (".htpasswd",          "CRITICAL", ".htpasswd 暴露，含加密密码"),
    ("wp-config.php.bak",  "CRITICAL", "WordPress 配置备份文件"),
    ("backup.sql",         "CRITICAL", "数据库备份文件暴露"),
    ("dump.sql",           "CRITICAL", "SQL dump 文件暴露"),
]


class SensitiveInfoScanner(BaseScanner):
    name = "sensitive"
    passive = True

    def run(self):
        log("INFO", "敏感信息泄露检测...")
        self._scan_page()
        self.map(self._check_file, EXPOSED_FILES)

    def _scan_page(self):
        r = self.baseline()
        if not r:
            return
        for name, (pattern, severity) in PATTERNS.items():
            matches = re.findall(pattern, r.text)
            if matches:
                sample = str(matches[0])[:60]
                icon = "VULN" if severity in ["CRITICAL", "HIGH"] else "WARN"
                log(icon, f"[敏感信息] {name} ({len(matches)} 处匹配)")
                self.add("敏感信息泄露", severity,
                         f"源码/响应中发现 {name} ({len(matches)} 处)",
                         sample, url=self.target)

    def _check_file(self, entry):
        path, severity, desc = entry
        url = self.url(path)
        r = self.get(url, allow_redirects=False)
        if r and r.status_code == 200 and len(r.text) > 10:
            if path == ".git/HEAD" and "ref:" not in r.text:
                return None
            if path == ".env" and "=" not in r.text:
                return None
            log("VULN", f"[文件暴露] {path} → {desc}")
            self.add("文件暴露", severity, desc, r.text[:100], url=url)
            return url
        return None
