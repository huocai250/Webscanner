"""
默认凭据 & 弱口令检测模块
Author: 火柴 | GitHub: huocai250
"""
import re
from core.scanner import BaseScanner
from core.colors import log

# 常见管理页面 + 默认凭据
TARGETS = [
    # (路径, 用户名字段, 密码字段, 成功特征)
    ("/wp-login.php",        "log",      "pwd",      ["Dashboard", "wp-admin"]),
    ("/admin",               "username", "password", ["dashboard", "logout", "Welcome"]),
    ("/admin/login",         "username", "password", ["dashboard", "logout"]),
    ("/login",               "username", "password", ["dashboard", "logout", "profile"]),
    ("/administrator/index.php", "username", "passwd", ["Control Panel", "Administrator"]),
    ("/user/login",          "name",     "pass",     ["Log out", "My account"]),
    ("/phpmyadmin/",         "pma_username","pma_password", ["phpMyAdmin", "sql"]),
    ("/manager/html",        "username", "password", ["Tomcat", "Manager App"]),
]

WEAK_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("admin",  ""),
    ("root",   "root"),
    ("root",   "toor"),
    ("root",   "password"),
    ("root",   "123456"),
    ("test",   "test"),
    ("user",   "user"),
    ("guest",  "guest"),
    ("admin",  "admin@123"),
    ("admin",  "P@ssw0rd"),
    ("administrator", "administrator"),
    ("administrator", "admin"),
]

# 速率限制特征
RATE_LIMIT_SIGS = [
    "too many", "rate limit", "blocked", "lockout",
    "captcha", "try again", "429", "throttle",
]


class WeakCredScanner(BaseScanner):
    def run(self):
        log("INFO", "弱口令 & 默认凭据检测...")
        for path, user_field, pass_field, success_sigs in TARGETS:
            url = self.url(path)
            r = self.get(url)
            if not r or r.status_code not in [200, 302, 401]:
                continue
            log("INFO", f"  测试登录页: {path}")
            if self._is_rate_limited(r.text):
                log("WARN", f"  {path} 存在速率限制保护")
                self.result.add("弱口令", "INFO",
                                f"登录页 {path} 有速率限制保护", url=url)
                continue
            self._try_creds(url, user_field, pass_field, success_sigs)

    def _try_creds(self, url, user_field, pass_field, success_sigs):
        for username, password in WEAK_CREDS:
            data = {user_field: username, pass_field: password}
            r = self.post(url, data=data, allow_redirects=True)
            if not r:
                continue
            if self._is_rate_limited(r.text):
                log("WARN", f"  触发速率限制，停止爆破: {url}")
                return
            if self._is_success(r, success_sigs):
                log("VULN", f"[弱口令] 登录成功！{url} → {username}:{password}")
                self.result.add("弱口令", "CRITICAL",
                                f"使用弱凭据登录成功: {username}:{password}",
                                f"URL: {url}", url=url)
                return

    def _is_success(self, r, sigs):
        if r.status_code in [200, 302]:
            return any(s.lower() in r.text.lower() for s in sigs)
        return False

    def _is_rate_limited(self, text):
        return any(s in text.lower() for s in RATE_LIMIT_SIGS)
