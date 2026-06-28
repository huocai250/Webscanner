"""
SSL/TLS 检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 弃用 TLSVersion 枚举检测旧协议（触发 DeprecationWarning）
  改用 OpenSSL 命令行或握手失败判断
- 证书日期格式处理更健壮
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import ssl
import socket
import warnings
from datetime import datetime
from urllib.parse import urlparse
from core.scanner import BaseScanner

# 已知不安全的密码套件片段
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"]


class SSLChecker(BaseScanner):
    def run(self):
        _before = self.result.total()
        if not self.target.startswith("https"):
            log.warning("[VULN] " +  "目标未使用 HTTPS，数据明文传输")
            self.result.add("SSL/TLS", "HIGH", "目标未使用 HTTPS，通信未加密", url=self.target)
            return
        log.info( "SSL/TLS 检测...")
        hostname = urlparse(self.target).hostname
        port     = urlparse(self.target).port or 443
        self._check_cert(hostname, port)
        self._check_old_protocols(hostname, port)
        self._check_weak_ciphers(hostname, port)
        self._log_module_done("SSL/TLS", _before)

    def _check_cert(self, hostname: str, port: int):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(self.timeout)
                s.connect((hostname, port))
                cert = s.getpeercert()
                tls_ver = s.version()

            # 有效期
            not_after = cert.get("notAfter", "")
            try:
                expire = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                expire = datetime.strptime(not_after, "%b  %d %H:%M:%S %Y %Z")
            days_left = (expire - datetime.utcnow()).days
            log.info( f"证书到期: {expire.strftime('%Y-%m-%d')} (剩余 {days_left} 天)")
            log.info( f"TLS 版本: {tls_ver}")

            if days_left < 0:
                self.result.add("SSL/TLS", "CRITICAL", "证书已过期！", url=self.target)
            elif days_left < 14:
                self.result.add("SSL/TLS", "HIGH",
                                f"证书 {days_left} 天后过期", url=self.target)
            elif days_left < 30:
                self.result.add("SSL/TLS", "MEDIUM",
                                f"证书 {days_left} 天后过期", url=self.target)

            # 主体 & 颁发者
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer",  []))
            log.info( f"颁发给: {subject.get('commonName','N/A')}")
            log.info( f"颁发者: {issuer.get('organizationName','N/A')}")

            # SAN
            if not cert.get("subjectAltName"):
                self.result.add("SSL/TLS", "LOW",
                                "证书未配置 SAN (Subject Alternative Name)", url=self.target)

            # 自签证书
            if subject == issuer:
                self.result.add("SSL/TLS", "MEDIUM",
                                "可能为自签证书（颁发者 == 主体）", url=self.target)

        except ssl.SSLCertVerificationError as e:
            log.warning("[VULN] " +  f"证书验证失败: {e}")
            self.result.add("SSL/TLS", "HIGH", f"证书验证错误: {e}", url=self.target)
        except ssl.SSLError as e:
            log.warning("[VULN] " +  f"SSL 握手错误: {e}")
            self.result.add("SSL/TLS", "HIGH", f"SSL 配置错误: {e}", url=self.target)
        except Exception as e:
            log.warning( f"SSL 检测异常: {type(e).__name__}: {e}")

    def _check_old_protocols(self, hostname: str, port: int):
        """
        检测 TLS 1.0 / 1.1 支持情况
        通过强制设置 maximum_version 测试，捕获 DeprecationWarning
        """
        old_protos = []
        for name, tls_ver in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                               ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx.minimum_version = tls_ver
                    ctx.maximum_version = tls_ver
                with ctx.wrap_socket(socket.socket(),
                                     server_hostname=hostname) as s:
                    s.settimeout(3)
                    s.connect((hostname, port))
                old_protos.append(name)
            except Exception:
                pass  # 连接失败 = 不支持该版本

        if old_protos:
            log.warning( f"支持旧版 TLS: {', '.join(old_protos)}")
            self.result.add("SSL/TLS", "MEDIUM",
                            f"服务器支持不安全协议: {', '.join(old_protos)}",
                            url=self.target)

    def _check_weak_ciphers(self, hostname: str, port: int):
        """检测是否支持弱密码套件"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(self.timeout)
                s.connect((hostname, port))
                cipher_name = s.cipher()[0] if s.cipher() else ""
                if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
                    log.warning( f"使用弱密码套件: {cipher_name}")
                    self.result.add("SSL/TLS", "MEDIUM",
                                    f"使用弱密码套件: {cipher_name}", url=self.target)
        except Exception as e:
            log.debug(f"弱密码套件检测失败: {e}")
