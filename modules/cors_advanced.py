"""
CORS 高级绕过检测模块（主动）
Author: 火柴 | GitHub: huocai250

基础 CORS 模块检查「反射任意 Origin + 凭据」；本模块补充常见的 ACAO 白名单
绕过模式：null 源、子域名信任、前后缀匹配缺陷（evil-target.com / target.com.evil.com）、
以及非 HTTPS 源被信任。仅发送带 Origin 头的请求观察响应，不窃取任何数据。
"""
from urllib.parse import urlparse
from core.scanner import BaseScanner
from core.colors import log


class CORSAdvancedScanner(BaseScanner):
    name = "corsadv"
    passive = False

    def run(self):
        log("INFO", "CORS 高级绕过检测（null/子域/前后缀/明文源）...")
        host = urlparse(self.target).netloc
        base_domain = host.split(":")[0]
        origins = [
            ("null", "null 源被信任（sandbox iframe/重定向可伪造）", "HIGH"),
            (f"https://evil-{base_domain}", "前缀匹配缺陷（evil-<域> 被信任）", "HIGH"),
            (f"https://{base_domain}.evil.example", "后缀匹配缺陷（<域>.evil 被信任）", "HIGH"),
            (f"https://sub.{base_domain}", "任意子域被信任（子域接管即可利用）", "MEDIUM"),
            (f"http://{base_domain}", "明文 http 源被信任（可被降级/中间人利用）", "MEDIUM"),
        ]
        for origin, desc, sev in origins:
            r = self.get(self.target, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin or (origin == "null" and acao == "null"):
                credflag = acac.lower() == "true"
                real_sev = "CRITICAL" if credflag and sev == "HIGH" else sev
                log("VULN", f"[CORS绕过] {origin} 被反射" + ("（含凭据）" if credflag else ""))
                self.add("CORS", real_sev,
                         f"CORS 白名单绕过：{desc}"
                         + ("，且 Allow-Credentials=true（可读取带凭据的跨源响应）"
                            if credflag else ""),
                         evidence=f"Origin: {origin} -> ACAO: {acao} ACAC: {acac}",
                         url=self.target,
                         confidence="确认" if credflag else "疑似")
                return
