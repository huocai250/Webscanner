"""
子域名枚举模块（主动 / 需网络与授权）
Author: 火柴 | GitHub: huocai250

基于字典对目标主域做 DNS 解析枚举，发现存活子域名。属于信息收集/攻击面
梳理，请仅在获得授权、且这些子域属于目标范围时使用。

说明：仅做 DNS 解析（socket.gethostbyname），不对子域发起进一步扫描；
如需扫描发现的子域，请在授权范围内单独指定目标。
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.scanner import BaseScanner
from core.colors import log

DEFAULT_SUBS = [
    "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
    "test", "dev", "staging", "api", "app", "portal", "vpn", "m", "mobile",
    "blog", "shop", "store", "cdn", "static", "img", "assets", "media",
    "docs", "help", "support", "status", "dashboard", "panel", "cpanel",
    "git", "gitlab", "jenkins", "ci", "jira", "wiki", "demo", "beta",
    "internal", "intranet", "corp", "office", "remote", "gateway", "proxy",
    "db", "database", "mysql", "redis", "cache", "backup", "old", "new",
    "secure", "login", "auth", "sso", "oauth", "id", "account", "user",
    "monitor", "grafana", "kibana", "prometheus", "es", "elastic", "solr",
]


class SubdomainScanner(BaseScanner):
    name = "subdomain"
    passive = False

    def run(self):
        domain = self.config.host()
        # 去掉可能的 www. 前缀，取主域
        base = domain[4:] if domain.startswith("www.") else domain
        if not base or base.replace(".", "").isdigit():
            log("INFO", "目标为 IP 或无有效域名，跳过子域名枚举")
            return

        words = self._load_words()
        log("INFO", f"子域名枚举（{len(words)} 条字典 -> {base}）...")
        found = []
        with ThreadPoolExecutor(max_workers=min(50, self.threads * 4)) as ex:
            futs = {ex.submit(self._resolve, f"{w}.{base}"): w for w in words}
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    host, ip = res
                    found.append((host, ip))
                    log("VULN", f"[子域名] {host} -> {ip}")

        if found:
            listing = ", ".join(f"{h}({ip})" for h, ip in sorted(found))
            self.add("信息泄露", "INFO",
                     f"发现 {len(found)} 个存活子域名: {listing}",
                     url=base, confidence="信息")
        else:
            log("INFO", "  未发现存活子域名")

    def _load_words(self):
        if self.config.subdomain_wordlist:
            try:
                with open(self.config.subdomain_wordlist, encoding="utf-8",
                          errors="ignore") as f:
                    return [ln.strip() for ln in f if ln.strip()
                            and not ln.startswith("#")]
            except OSError as e:
                log("WARN", f"子域名字典读取失败: {e}，使用内置字典")
        return DEFAULT_SUBS

    @staticmethod
    def _resolve(host):
        try:
            ip = socket.gethostbyname(host)
            return (host, ip)
        except (socket.gaierror, OSError):
            return None
