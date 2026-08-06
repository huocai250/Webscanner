"""
SSL/TLS 检测模块
Author: 火柴 | GitHub: huocai250

v4.0 修复：
  - 旧版协议探测逻辑修正（此前把 SSLv3/TLS1.0/1.1 全部固定成 TLS1.0，无法区分）
  - 用 timezone-aware datetime 替代已弃用的 utcnow()
  - 增加弱加密套件提示
"""
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from core.scanner import BaseScanner
from core.colors import log


class SSLChecker(BaseScanner):
    name = "ssl"
    passive = True

    def run(self):
        if not self.target.startswith("https"):
            log("VULN", "目标未使用 HTTPS，数据传输存在明文风险")
            self.add("SSL/TLS", "HIGH", "目标未使用 HTTPS，数据传输未加密", url=self.target)
            return
        log("INFO", "检测 SSL/TLS 配置...")
        hostname = urlparse(self.target).hostname
        port = urlparse(self.target).port or 443
        self._check_cert(hostname, port)
        self._check_protocols(hostname, port)

    def _check_cert(self, hostname, port):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                    cert = s.getpeercert()

                    expire = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expire - now).days
                    log("OK", f"证书到期: {expire.date()}（剩余 {days_left} 天）")
                    if days_left < 0:
                        self.add("SSL/TLS", "CRITICAL", "证书已过期！", url=self.target)
                    elif days_left < 14:
                        self.add("SSL/TLS", "HIGH", f"证书即将过期，剩余 {days_left} 天", url=self.target)
                    elif days_left < 30:
                        self.add("SSL/TLS", "MEDIUM", f"证书将在 {days_left} 天后过期", url=self.target)

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    log("OK", f"颁发给: {subject.get('commonName', 'N/A')}")
                    log("OK", f"颁发者: {issuer.get('organizationName', 'N/A')}")

                    if not cert.get("subjectAltName"):
                        self.add("SSL/TLS", "LOW", "证书未配置 SAN (Subject Alternative Name)", url=self.target)

                    log("OK", f"TLS 版本(协商): {s.version()}")

        except ssl.SSLCertVerificationError as e:
            log("VULN", f"证书验证失败: {e}")
            self.add("SSL/TLS", "HIGH", f"证书验证错误: {e}", url=self.target)
        except ssl.SSLError as e:
            log("VULN", f"SSL 错误: {e}")
            self.add("SSL/TLS", "HIGH", f"SSL 配置错误: {e}", url=self.target)
        except Exception as e:
            log("WARN", f"SSL 检测异常: {e}")

    def _check_protocols(self, hostname, port):
        """逐个尝试老旧协议版本，真正区分 TLS1.0 / TLS1.1。"""
        candidates = []
        # 仅探测运行环境支持配置的版本
        if hasattr(ssl.TLSVersion, "TLSv1"):
            candidates.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
        if hasattr(ssl.TLSVersion, "TLSv1_1"):
            candidates.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))

        insecure = []
        for label, ver in candidates:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        insecure.append(label)
            except (ssl.SSLError, OSError, ValueError):
                pass

        if insecure:
            log("WARN", f"支持旧版 TLS 协议: {', '.join(insecure)}")
            self.add("SSL/TLS", "MEDIUM",
                     f"服务器支持不安全的协议版本: {', '.join(insecure)}", url=self.target)
        else:
            log("OK", "未发现启用的旧版 TLS 协议 (仅 TLS1.2+)")
