"""
危险 HTTP 方法检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 使用 BaseScanner.request 统一调用，确保重试和超时生效
- PUT 测试使用更无害的文件名，且更严格验证响应
- 避免 DELETE 测试删除真实文件
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


from core.scanner import BaseScanner

_TEST_FILE = "webscanner_put_test_delete_me.txt"


class HTTPMethodScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info( "危险 HTTP 方法检测...")
        self._check_options()
        self._check_trace()
        self._check_put()
        self._check_delete()
        self._log_module_done("危险HTTP方法", _before)

    def _check_options(self):
        r = self.request("OPTIONS", self.target)
        if not r:
            return
        allow = r.headers.get("Allow", "") or r.headers.get("Public", "")
        if allow:
            log.info( f"Allow 头: {allow}")
            dangerous = [m for m in ["PUT", "DELETE", "PATCH", "CONNECT", "TRACE"]
                         if m in allow.upper()]
            if dangerous:
                log.warning( f"Allow 头含危险方法: {', '.join(dangerous)}")
                self.result.add("HTTP 方法", "MEDIUM",
                                f"服务器 Allow 头包含危险方法: {', '.join(dangerous)}",
                                f"Allow: {allow}", url=self.target)

    def _check_trace(self):
        marker = "x-webscanner-trace-marker"
        r = self.request("TRACE", self.target,
                         headers={"X-Custom-Header": marker})
        if r and r.status_code == 200 and marker in r.text:
            log.warning("[VULN] " +  "[XST] TRACE 方法已启用，存在跨站追踪风险")
            self.result.add("HTTP 方法", "MEDIUM",
                            "TRACE 方法已启用（Cross-Site Tracing 风险）",
                            url=self.target)

    def _check_put(self):
        test_url = self.build_url(_TEST_FILE)
        r = self.request("PUT", test_url,
                         data=b"webscanner_test_content",
                         headers={"Content-Type": "text/plain"})
        if r and r.status_code in [200, 201, 204]:
            log.warning("[VULN] " +  f"[PUT] HTTP PUT 上传成功！({r.status_code})")
            self.result.add("HTTP 方法", "HIGH",
                            "HTTP PUT 方法已启用，可上传任意文件",
                            f"状态码: {r.status_code}", url=test_url)
            # 清理测试文件
            self.request("DELETE", test_url)
        elif r:
            log.info( f"PUT 方法: {r.status_code}（不可用）")

    def _check_delete(self):
        # 只测试明显不存在的路径，避免删真实资源
        test_url = self.build_url("__nonexistent_webscanner_file_xyz__.txt")
        r = self.request("DELETE", test_url)
        if r and r.status_code in [200, 204]:
            log.warning( "[DELETE] HTTP DELETE 方法可能已启用")
            self.result.add("HTTP 方法", "MEDIUM",
                            "HTTP DELETE 方法已启用，可能删除服务器文件",
                            url=self.target)
