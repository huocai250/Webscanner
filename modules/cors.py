"""
CORS 配置错误检测模块
Author: 火柴 | GitHub: huocai250

修复:
- 添加 allow_redirects=False，避免跟随跳转后丢失 CORS 响应头
- 细化检测逻辑
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


from core.scanner import BaseScanner

TEST_ORIGINS = [
    "https://evil.com",
    "https://evil.target.com",
    "null",
    "https://attacker.com",
    "http://localhost",
]


class CORSScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info( "CORS 配置检测...")
        self._check_cors()
        self._log_module_done("CORS", _before)

    def _check_cors(self):
        for origin in TEST_ORIGINS:
            # 修复：必须禁用重定向，否则跟随跳转后 CORS 头会丢失
            r = self.get(self.target,
                         headers={"Origin": origin},
                         allow_redirects=False)
            if not r:
                continue

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            if not acao:
                continue

            # 1. 通配符
            if acao == "*":
                if acac == "true":
                    # 通配符 + credentials 是无效配置，但仍需记录
                    log.warning( "CORS: Access-Control-Allow-Origin:* + Credentials:true（浏览器会拒绝，但配置混乱）")
                    self.result.add("CORS", "MEDIUM",
                                    "CORS 同时使用通配符和 Credentials（配置矛盾）",
                                    url=self.target)
                else:
                    log.warning( "CORS: Access-Control-Allow-Origin: * 通配符")
                    self.result.add("CORS", "LOW",
                                    "CORS 使用通配符，任意域可跨域读取（无凭据）",
                                    url=self.target)
                return

            # 2. 反射 Origin + Credentials = true（高危）
            if acao == origin and acac == "true":
                log.warning("[VULN] " +  f"[CORS] 反射 Origin + Credentials=true → 可窃取认证信息！")
                self.result.add("CORS", "HIGH",
                                "CORS 高危配置：反射任意 Origin 且允许携带凭据",
                                f"Origin: {origin} | ACAO: {acao} | ACAC: {acac}",
                                url=self.target)
                return

            # 3. 反射 Origin（无 credentials）
            if acao == origin:
                log.warning( f"CORS 反射了请求 Origin: {origin}")
                self.result.add("CORS", "MEDIUM",
                                "CORS 反射任意 Origin（无凭据），可能泄露响应内容",
                                f"Origin: {origin}", url=self.target)

            # 4. null Origin
            if acao == "null":
                log.warning( "CORS 允许 null Origin（可被沙箱 iframe 利用）")
                self.result.add("CORS", "MEDIUM",
                                "CORS 允许 null Origin，可被沙箱 iframe 利用",
                                url=self.target)
