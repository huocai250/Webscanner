"""
端口扫描模块
Author: 火柴 | GitHub: huocai250
v4.0: 增加 banner 抓取以提高服务识别准确性
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from core.scanner import BaseScanner
from core.colors import log

PORTS = {
    21:    ("FTP",           "HIGH",    "FTP 明文传输，存在凭据泄露风险"),
    22:    ("SSH",           "INFO",    "SSH 服务开放"),
    23:    ("Telnet",        "CRITICAL","Telnet 明文传输，高危协议"),
    25:    ("SMTP",          "LOW",     "SMTP 邮件服务"),
    53:    ("DNS",           "INFO",    "DNS 服务开放"),
    80:    ("HTTP",          "INFO",    "HTTP 服务"),
    110:   ("POP3",          "MEDIUM",  "POP3 邮件服务"),
    135:   ("MSRPC",         "HIGH",    "Windows RPC 服务，常见攻击面"),
    139:   ("NetBIOS",       "HIGH",    "NetBIOS，常见内网漏洞利用服务"),
    143:   ("IMAP",          "LOW",     "IMAP 邮件服务"),
    443:   ("HTTPS",         "INFO",    "HTTPS 服务"),
    445:   ("SMB",           "CRITICAL","SMB 服务，EternalBlue 等漏洞高发"),
    1433:  ("MSSQL",         "HIGH",    "MSSQL 数据库暴露"),
    1521:  ("Oracle",        "HIGH",    "Oracle 数据库暴露"),
    2181:  ("ZooKeeper",     "HIGH",    "ZooKeeper 未授权访问风险"),
    2375:  ("Docker API",    "CRITICAL","Docker Remote API 未授权访问"),
    3306:  ("MySQL",         "HIGH",    "MySQL 数据库暴露"),
    3389:  ("RDP",           "HIGH",    "RDP 远程桌面，暴力破解高发"),
    4848:  ("GlassFish",     "HIGH",    "GlassFish 管理控制台"),
    5432:  ("PostgreSQL",    "HIGH",    "PostgreSQL 数据库暴露"),
    5900:  ("VNC",           "HIGH",    "VNC 远程桌面服务"),
    6379:  ("Redis",         "CRITICAL","Redis 未授权访问高发端口"),
    7001:  ("WebLogic",      "HIGH",    "WebLogic 常见反序列化漏洞"),
    8080:  ("HTTP-Alt",      "LOW",     "HTTP 备用端口"),
    8161:  ("ActiveMQ",      "HIGH",    "ActiveMQ 管理台"),
    8443:  ("HTTPS-Alt",     "LOW",     "HTTPS 备用端口"),
    8888:  ("Jupyter",       "HIGH",    "Jupyter Notebook 可能未授权"),
    9200:  ("Elasticsearch", "CRITICAL","Elasticsearch 未授权访问高发"),
    9300:  ("ES Cluster",    "HIGH",    "Elasticsearch 集群通信端口"),
    11211: ("Memcached",     "CRITICAL","Memcached 未授权访问高发"),
    27017: ("MongoDB",       "CRITICAL","MongoDB 未授权访问高发"),
    50000: ("SAP",           "HIGH",    "SAP ICM 服务"),
    50070: ("Hadoop HDFS",   "HIGH",    "Hadoop HDFS NameNode"),
}


class PortScanner(BaseScanner):
    name = "ports"
    passive = False   # 主动连接目标端口，非被动

    def run(self):
        log("INFO", f"端口扫描 ({len(PORTS)} 个目标端口)...")
        hostname = urlparse(self.target).hostname
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            log("WARN", "无法解析主机，跳过端口扫描")
            return

        open_ports = []
        workers = min(self.threads * 3, 100)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self._scan, ip, p): p for p in PORTS}
            for fut in as_completed(futures):
                port = futures[fut]
                banner = fut.result()
                if banner is not False:
                    open_ports.append((port, banner))

        for port, banner in sorted(open_ports):
            name, severity, desc = PORTS[port]
            icon = "VULN" if severity in ("CRITICAL", "HIGH") else "OK"
            extra = f" | Banner: {banner}" if banner else ""
            log(icon, f"端口 {port}/{name} 开放 — {desc}{extra}")
            self.add("端口扫描", severity,
                     f"开放端口: {port}/{name} — {desc}",
                     evidence=banner or "", url=f"{hostname}:{port}")

    def _scan(self, host, port):
        """返回 False=关闭；否则返回 banner 字符串（可能为空）。"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((host, port)) != 0:
                s.close()
                return False
            # 尝试抓取 banner
            banner = ""
            try:
                s.settimeout(1.0)
                data = s.recv(128)
                banner = data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:80]
            except Exception:
                pass
            s.close()
            return banner
        except Exception:
            return False
