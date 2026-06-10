"""
目录与文件枚举模块
Author: 火柴 | GitHub: huocai250

修复:
- _soft404_len 从构造函数移到 run()，避免构造期网络失败导致永久失效
- future.result() 包裹 try-except，防止线程异常传播崩溃主程序
- 软404采样改为3次取平均，更稳定
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.scanner import BaseScanner

BUILTIN_WORDLIST = [
    "admin", "administrator", "admin.php", "admin.html", "admin/login",
    "manage", "manager", "dashboard", "backend", "panel", "control",
    "adminpanel", "admin_area", "admin-console", "superadmin",
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
    "api-docs", "openapi.json", "openapi.yaml", "redoc",
    ".git", ".git/HEAD", ".git/config", ".git/index",
    ".env", ".env.local", ".env.production", ".env.backup",
    ".htaccess", ".htpasswd", ".bash_history",
    "web.config", "app.config", "config.php", "config.json",
    "configuration.php", "settings.py", "settings.php",
    "database.yml", "db.php", "database.php",
    "composer.json", "package.json", "yarn.lock",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "readme.md", "README.md", "README.txt", "CHANGELOG.md",
    "LICENSE", "INSTALL.md", "SECURITY.md",
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "database.sql", "dump.sql", "site.zip",
    "www.zip", "html.zip", "old", "bak", "temp", "tmp",
    "upload", "uploads", "files", "file", "media", "images",
    "img", "static", "assets", "resources",
    "logs", "log", "error.log", "access.log", "debug.log",
    "wp-admin", "wp-login.php", "wp-config.php", "xmlrpc.php",
    "wp-content/debug.log", "administrator",
    "phpmyadmin", "pma", "myadmin", "adminer.php", "adminer",
    "actuator", "actuator/env", "actuator/health", "actuator/mappings",
    "actuator/trace", "actuator/dump", "actuator/beans",
    "health", "status", "metrics", "server-status",
    ".well-known/security.txt", "security.txt",
    "console", "terminal", "cgi-bin",
    "login", "signin", "logout", "register", "signup",
    "robots.txt", "sitemap.xml", ".DS_Store", "crossdomain.xml",
]

HIGH_RISK = {
    ".git", ".env", "phpinfo", "shell", "cmd", "exec", "eval",
    "webshell", "backup.sql", "database.sql", "dump.sql",
    ".htpasswd", ".bash_history", "actuator",
    "web.config", "config.php", "settings.py",
}

SOFT_404_SIGS = [
    "page not found", "404", "not found", "does not exist",
    "页面不存在", "找不到页面", "no encontrado",
]


class DirBuster(BaseScanner):
    def __init__(
        self,
        target: str,
        result,
        wordlist_file: str = None,
        **kwargs,
    ):
        super().__init__(target, result, **kwargs)
        self.wordlist       = self._load_wordlist(wordlist_file)
        self._soft404_len   = -1   # 修复：延迟到 run() 采样

    def _load_wordlist(self, path: str) -> list:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                custom = [l.strip() for l in f
                          if l.strip() and not l.startswith("#")]
            log.info( f"自定义字典: {len(custom)} 条 + 内置 {len(BUILTIN_WORDLIST)} 条")
            return list(dict.fromkeys(BUILTIN_WORDLIST + custom))
        return BUILTIN_WORDLIST

    def _sample_soft404(self) -> int:
        """修复：在 run() 里采样，避免构造期失败导致永久失效"""
        lengths = []
        for suffix in ["__ws_nx_1__", "__ws_nx_2__", "__ws_nx_3__"]:
            r = self.get(self.build_url(suffix))
            if r:
                lengths.append(len(r.text))
        return int(sum(lengths) / len(lengths)) if lengths else 0

    def run(self):
        # 修复：在 run() 里采样软404基准
        self._soft404_len = self._sample_soft404()
        log.info( f"目录枚举 ({len(self.wordlist)} 条, {self.threads} 线程, "
            f"软404基准={self._soft404_len}b)...")

        found = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check, p): p for p in self.wordlist}
            for future in as_completed(futures):
                try:
                    res = future.result()   # 修复：捕获线程异常
                    if res:
                        found.append(res)
                except Exception:
                    pass

        log.info( f"目录枚举完成，发现 {len(found)} 个路径")

    def _check(self, path: str):
        url = self.build_url(path)
        r   = self.get(url, allow_redirects=False)
        if not r or r.status_code not in [200, 301, 302, 401, 403]:
            return None

        # 软404过滤
        if r.status_code == 200 and self._soft404_len > 0:
            if abs(len(r.text) - self._soft404_len) < 50:
                return None
            tl = r.text.lower()
            if any(s in tl for s in SOFT_404_SIGS) and len(r.text) < 5000:
                return None

        is_high  = any(h in path.lower() for h in HIGH_RISK)
        severity = ("HIGH"   if r.status_code == 200 and is_high else
                    "MEDIUM" if r.status_code == 200 else "LOW")

        label    = {200: "可访问", 301: "→", 302: "→",
                    401: "需认证", 403: "禁止"}.get(r.status_code, str(r.status_code))
        redir    = r.headers.get("Location", "")
        color    = Colors.RED if severity == "HIGH" else Colors.YELLOW

        msg = f"[{r.status_code} {label}] {color}{url}{Colors.RESET}" + (f" {redir}" if redir else "")
        if severity == "HIGH":
            log.warning(f"[VULN] {msg}")
        else:
            log.warning(msg)

        detail = f"[{r.status_code}] {label}: /{path}" + (f" {redir}" if redir else "")
        self.result.add("目录枚举", severity, detail, url=url)
        return url
