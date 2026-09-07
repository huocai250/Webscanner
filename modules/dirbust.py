"""
目录与文件枚举模块
Author: 火柴 | GitHub: huocai250
v4.0: 适配新基类；用基线 404 长度过滤软 404（wildcard 响应）
"""
import os
from core.scanner import BaseScanner
from core.colors import log, Colors


BUILTIN_WORDLIST = [
    "admin", "administrator", "admin.php", "admin.html", "admin/login",
    "manage", "manager", "dashboard", "backend", "panel", "control",
    "adminpanel", "admin_area", "admin-console", "superadmin",
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
    "api-docs", "openapi.json", "openapi.yaml", "redoc",
    ".git", ".git/HEAD", ".git/config", ".git/index",
    ".env", ".env.local", ".env.production", ".env.backup",
    ".htaccess", ".htpasswd", ".bash_history", ".ssh/id_rsa",
    "web.config", "app.config", "config.php", "config.json",
    "configuration.php", "settings.py", "settings.php",
    "database.yml", "db.php", "database.php",
    "composer.json", "package.json", "yarn.lock", "Gemfile",
    "phpinfo.php", "info.php", "test.php", "debug.php", "phptest.php",
    "php.php", "eval.php", "shell.php", "cmd.php", "exec.php",
    "readme.md", "README.md", "README.txt", "CHANGELOG.md",
    "LICENSE", "INSTALL.md", "SECURITY.md",
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "database.sql", "dump.sql", "site.zip",
    "www.zip", "html.zip", "old", "bak", "temp", "tmp",
    "upload", "uploads", "files", "file", "media", "images",
    "img", "static", "assets", "resources",
    "logs", "log", "error.log", "access.log", "debug.log",
    "application.log", "server.log", "php_error.log",
    "wp-admin", "wp-login.php", "wp-config.php", "xmlrpc.php",
    "wp-content/debug.log",
    "phpmyadmin", "pma", "myadmin", "mysql", "mysqladmin",
    "adminer.php", "adminer",
    "actuator", "actuator/env", "actuator/health", "actuator/mappings",
    "actuator/trace", "actuator/dump", "actuator/beans", "actuator/metrics",
    "health", "status", "metrics", "monitor", "ping",
    "server-status", "server-info",
    ".well-known/security.txt", "security.txt",
    "console", "terminal", "webshell",
    "cgi-bin", "cgi-bin/admin.cgi",
    "login", "signin", "logout", "register", "signup",
    "forgot-password", "reset-password",
    "robots.txt", "sitemap.xml", ".DS_Store",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

HIGH_RISK_PATHS = {
    ".git", ".env", "phpinfo", "shell", "cmd", "exec", "eval",
    "webshell", "backup.sql", "database.sql", "dump.sql",
    ".htpasswd", ".bash_history", ".ssh", "id_rsa",
    "actuator", "web.config", "config.php", "settings.py",
}


class DirBuster(BaseScanner):
    name = "dirbust"
    passive = False   # 会对大量路径发起请求

    def __init__(self, ctx):
        super().__init__(ctx)
        self.wordlist = self._load_wordlist(self.config.wordlist_file)
        self._soft404_len = None

    def _load_wordlist(self, path):
        if path and os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                custom = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            log("OK", f"加载自定义字典: {len(custom)} 条")
            return sorted(set(BUILTIN_WORDLIST + custom))
        return BUILTIN_WORDLIST

    def run(self):
        log("INFO", f"目录枚举 ({len(self.wordlist)} 条字典，{self.threads} 线程)...")
        self.calibrate_soft404()
        found = self.map(self._check, self.wordlist)
        log("OK", f"目录枚举完成，发现 {len(found)} 个可访问路径")

    def _check(self, path):
        url = self.url(path)
        r = self.get(url, allow_redirects=False)
        if not r or r.status_code not in (200, 301, 302, 401, 403):
            return None
        # 过滤软 404（相似度）
        if r.status_code == 200 and self.is_soft404(r):
            return None

        is_high = any(h in path.lower() for h in HIGH_RISK_PATHS)
        severity = "HIGH" if (r.status_code == 200 and is_high) else \
                   "MEDIUM" if r.status_code == 200 else "LOW"

        label = {200: "可访问", 301: "重定向", 302: "重定向",
                 401: "需认证", 403: "禁止访问"}.get(r.status_code, str(r.status_code))

        icon = "VULN" if severity == "HIGH" else "WARN"
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW
        log(icon, f"[{r.status_code} {label}] {color}{url}{Colors.RESET}")
        self.add("目录枚举", severity, f"[{r.status_code}] {label}: {path}", url=url)
        return url
