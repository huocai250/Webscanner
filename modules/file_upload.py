"""
文件上传漏洞检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 使用 BaseScanner.request 替代 self.session.post（享受重试机制）
- multipart/form-data 上传时不能手动设 Content-Type（要让 requests 自动加 boundary）
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import re
from core.scanner import BaseScanner

UPLOAD_ENDPOINTS = [
    "/upload", "/uploads", "/file/upload", "/api/upload",
    "/image/upload", "/media/upload", "/attachment",
    "/admin/upload", "/files/upload", "/import",
    "/avatar", "/profile/upload", "/document/upload",
]

BYPASS_FILES = [
    ("shell.php",      b"<?php echo 'ws_upload_test'; ?>",  "application/octet-stream"),
    ("shell.php5",     b"<?php echo 'ws_upload_test'; ?>",  "application/octet-stream"),
    ("shell.phtml",    b"<?php echo 'ws_upload_test'; ?>",  "image/jpeg"),
    ("shell.php.jpg",  b"<?php echo 'ws_upload_test'; ?>",  "image/jpeg"),
    ("shell.PHP",      b"<?php echo 'ws_upload_test'; ?>",  "application/octet-stream"),
    ("shell.jsp",      b'<% out.println("ws_upload_test"); %>', "application/octet-stream"),
    ("shell.asp",      b'<% Response.Write("ws_upload_test") %>', "application/octet-stream"),
    ("image.jpg.php",  b"<?php echo 'ws_upload_test'; ?>",  "image/jpeg"),
    # 合法文件对照
    ("test.jpg",       b"\xff\xd8\xff\xe0" + b"JFIF",       "image/jpeg"),
]


class FileUploadScanner(BaseScanner):
    def run(self):
        log.info( "文件上传漏洞检测...")
        r = self.get(self.target)
        if not r:
            return
        # 从页面提取上传表单
        for action in self._find_upload_forms(r.text):
            log.info( f"  发现上传表单: {action}")
            self._test_upload(action)
        # 测试已知上传端点
        for endpoint in UPLOAD_ENDPOINTS:
            url = self.build_url(endpoint)
            r2  = self.get(url)
            if r2 and r2.status_code in [200, 302, 405]:
                self._test_upload(url)

    def _find_upload_forms(self, html: str) -> list:
        actions = []
        for m in re.finditer(
            r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>', html, re.I
        ):
            action = re.search(r'action=["\']([^"\']*)["\']', m.group(), re.I)
            url = action.group(1) if action else ""
            if url and not url.startswith("http"):
                url = self.build_url(url)
            actions.append(url or self.target)
        return actions

    def _test_upload(self, url: str):
        for fname, content, mime in BYPASS_FILES:
            files = {"file": (fname, content, mime)}
            # 修复：使用 BaseScanner.request 而非 self.session.post
            # 注意：files= 时 requests 自动设 Content-Type: multipart/form-data;boundary=...
            #       不能手动传 Content-Type，否则会覆盖掉 boundary 导致服务端解析失败
            r = self.request("POST", url, files=files)
            if not r or r.status_code not in [200, 201]:
                continue

            # 检查是否返回了文件路径
            path_match = re.search(
                r'["\']([^"\']*(?:upload|file|media|img)[^"\']*\.'
                + re.escape(fname.split(".")[-1]) + r')["\']',
                r.text, re.I
            )
            if path_match:
                uploaded_path = path_match.group(1)
                log.warning("[VULN] " +  f"[文件上传] 上传成功 {fname} → {uploaded_path}")
                self.result.add("文件上传", "CRITICAL",
                                f"危险文件上传成功: {fname}",
                                f"路径: {uploaded_path}", url=url)
                self._verify_execution(uploaded_path)
                return

            # 危险扩展名未被拦截
            if fname.endswith((".php", ".php5", ".phtml", ".jsp", ".asp",
                               ".aspx", ".PHP")):
                log.warning( f"[文件上传] {fname} 未被拦截 ({r.status_code})")
                self.result.add("文件上传", "HIGH",
                                f"危险文件 {fname} 上传未被服务端拦截",
                                f"状态码: {r.status_code}", url=url)

    def _verify_execution(self, path: str):
        if not path.startswith("/"):
            path = "/" + path
        r = self.get(self.build_url(path))
        if r and "ws_upload_test" in r.text:
            log.warning("[VULN] " +  f"[文件上传] 上传文件可被执行 (Webshell): {path}")
            self.result.add("文件上传", "CRITICAL",
                            "上传文件可被执行（已确认 Webshell）",
                            url=self.build_url(path))
