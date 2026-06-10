"""
子域名枚举模块
Author: 火柴 | GitHub: huocai250
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from core.scanner import BaseScanner

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "beta", "demo", "portal", "app", "m", "mobile", "shop", "store",
    "blog", "forum", "help", "support", "docs", "wiki", "cdn",
    "static", "assets", "media", "img", "images", "upload", "uploads",
    "vpn", "remote", "rdp", "ssh", "smtp", "pop", "imap", "webmail",
    "login", "auth", "sso", "account", "accounts", "user", "users",
    "db", "database", "mysql", "sql", "oracle", "redis", "mongo",
    "jenkins", "gitlab", "github", "ci", "cd", "deploy", "build",
    "jira", "confluence", "bitbucket", "svn", "git",
    "grafana", "kibana", "elastic", "monitor", "metrics", "logs",
    "backup", "bak", "old", "new", "v1", "v2",
    "uat", "qa", "preprod", "sandbox", "local",
    "intranet", "internal", "corp", "extranet",
    "ns", "ns1", "ns2", "dns", "mx",
    "proxy", "gateway", "firewall", "lb", "loadbalancer",
    "kubernetes", "k8s", "docker", "registry",
    "s3", "storage", "bucket", "files",
    "payment", "pay", "billing", "invoice",
]


class SubdomainScanner(BaseScanner):
    def run(self):
        hostname = urlparse(self.target).hostname or ""
        # 提取主域
        parts = hostname.split(".")
        if len(parts) < 2:
            log.info("[SKIP] " +  f"无法提取主域名: {hostname}")
            return
        base_domain = ".".join(parts[-2:])
        log.info( f"子域名枚举 (基域: {base_domain}, {len(SUBDOMAINS)} 个字典)...")

        found = []
        with ThreadPoolExecutor(max_workers=self.threads * 2) as executor:
            futures = {
                executor.submit(self._resolve, f"{sub}.{base_domain}"): sub
                for sub in SUBDOMAINS
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    found.append(result)

        log.info( f"子域名枚举完成，发现 {len(found)} 个")

    def _resolve(self, fqdn):
        try:
            ip = socket.gethostbyname(fqdn)
            log.info( f"子域名: {fqdn} → {ip}")
            self.result.add("子域名", "INFO",
                            f"发现子域名: {fqdn} ({ip})", url=f"http://{fqdn}")
            return fqdn
        except socket.gaierror:
            return None
        except Exception:
            return None
