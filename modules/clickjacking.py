"""
Clickjacking & 安全配置错误检测模块
Author: 火柴 | GitHub: huocai250

修复:
- _check_method_override 改用 BaseScanner.post（有重试机制）
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


from core.scanner import BaseScanner


class ClickjackingScanner(BaseScanner):
    def run(self):
        log.info( "Clickjacking & 安全配置检测...")
        self._check_clickjacking()
        self._check_directory_listing()
        self._check_debug_mode()
        self._check_error_disclosure()
        self._check_method_override()

    def _check_clickjacking(self):
        r = self.get(self.target)
        if not r:
            return
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            log.warning("[VULN] " +  "[Clickjacking] 缺少 iframe 保护头")
            self.result.add("Clickjacking", "MEDIUM",
                            "页面可被嵌入 iframe，存在 Clickjacking 风险",
                            url=self.target)
        elif xfo.upper() in ["ALLOW-FROM", "ALLOWALL"]:
            log.warning( f"[Clickjacking] X-Frame-Options 配置不安全: {xfo}")
            self.result.add("Clickjacking", "LOW",
                            f"X-Frame-Options 配置不当: {xfo}", url=self.target)

    def _check_directory_listing(self):
        for path in ["/uploads/", "/files/", "/images/",
                     "/static/", "/assets/", "/backup/", "/logs/"]:
            r = self.get(self.build_url(path))
            if not r or r.status_code != 200:
                continue
            if any(sig in r.text for sig in [
                "Index of", "Directory listing", "Parent Directory",
                "[DIR]", "apache/", "nginx/"
            ]):
                log.warning("[VULN] " +  f"[目录遍历] {path} 允许目录列表")
                self.result.add("目录遍历", "MEDIUM",
                                f"目录 {path} 开启了目录列表",
                                url=self.build_url(path))

    def _check_debug_mode(self):
        probes = [
            ("/?debug=true",  ["DEBUG", "Traceback", "stack trace", "Exception"]),
            ("/debug",        ["DEBUG", "routes", "config"]),
            ("/?env=dev",     ["development", "debug"]),
        ]
        for path, sigs in probes:
            r = self.get(self.build_url(path))
            if r and r.status_code == 200:
                if any(s.lower() in r.text.lower() for s in sigs):
                    log.warning( f"[调试模式] {path} 可能泄露调试信息")
                    self.result.add("调试模式", "MEDIUM",
                                    f"路径 {path} 可能暴露调试信息",
                                    url=self.build_url(path))
                    return

    def _check_error_disclosure(self):
        probes = [
            self.build_url("/" + "A" * 300),
            self.build_url("/?id=999999999999999"),
        ]
        error_sigs = [
            "Traceback (most recent call last)",
            "PHP Fatal error", "PHP Warning",
            "java.lang.", "com.sun.", "org.springframework.",
            "System.NullReferenceException",
            "ORA-", "SQLSTATE", "mysql_",
        ]
        for url in probes:
            r = self.get(url)
            if r:
                found = [s for s in error_sigs if s in r.text]
                if found:
                    log.warning( f"[错误信息泄露] {found[0]}")
                    self.result.add("错误信息泄露", "MEDIUM",
                                    f"服务器暴露详细错误: {found[0]}",
                                    url=url)
                    break

    def _check_method_override(self):
        """修复：使用 BaseScanner.post 而非 self.session.post"""
        r = self.post(
            self.target,
            extra_headers={
                "X-HTTP-Method-Override": "DELETE",
                "X-Method-Override": "DELETE",
            }
        )
        if r and r.status_code in [200, 204]:
            log.warning( "[方法覆盖] 服务器可能支持 X-HTTP-Method-Override")
            self.result.add("HTTP 方法覆盖", "LOW",
                            "服务器支持 X-HTTP-Method-Override 请求头",
                            url=self.target)
