"""
CORS 配置错误检测模块
Author: 火柴 | GitHub: huocai250
v4.0: 适配新基类
"""
from core.scanner import BaseScanner
from core.colors import log

TEST_ORIGINS = [
    "https://evil.example",
    "null",
    "https://attacker.example",
]


class CORSScanner(BaseScanner):
    name = "cors"
    passive = True

    def run(self):
        log("INFO", "CORS 配置检测...")
        for origin in TEST_ORIGINS:
            r = self.get(self.target, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                log("WARN", "CORS 配置: Access-Control-Allow-Origin: * (通配符)")
                self.add("CORS", "LOW",
                         "CORS 使用通配符 (*)，可能允许任意域跨域读取", url=self.target)
                return

            if acao == origin and acac.lower() == "true":
                log("VULN", "[CORS] 反射 Origin + Credentials=true → 高危！")
                self.add("CORS", "HIGH",
                         "CORS 配置错误：反射任意 Origin 且允许凭据",
                         f"Origin: {origin} | ACAO: {acao} | ACAC: {acac}", url=self.target)
                return

            if acao == origin:
                log("WARN", f"CORS 反射了请求 Origin: {origin}")
                self.add("CORS", "MEDIUM",
                         "CORS 配置可能过于宽松，反射了任意 Origin",
                         f"Origin: {origin}", url=self.target)

            if acao == "null":
                log("WARN", "CORS 允许 null Origin（沙箱 iframe 可利用）")
                self.add("CORS", "MEDIUM",
                         "CORS 允许 null Origin，可被沙箱 iframe 利用", url=self.target)
