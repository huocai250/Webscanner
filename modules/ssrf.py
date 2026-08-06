"""
SSRF（服务端请求伪造）检测模块（主动 / 检测导向）
Author: 火柴 | GitHub: huocai250

向可能触发服务端请求的参数注入一个**你控制的 canary URL**，若服务端确实
发起了对 canary 的请求（需配合带外 collaborator 观测），即存在 SSRF。
带内层面，本模块通过响应差异/错误特征给出「疑似」提示。

安全边界：本模块**只做检测** —— 判断服务端是否会向外部地址发起请求。
它**不读取云元数据(169.254.169.254)、不探测内网、不读取本地文件**。
这些属于利用行为，本工具不实现。请将 canary 配置为你自己的 collaborator。
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 常见会触发服务端取 URL 的参数名
SSRF_PARAMS = ["url", "uri", "link", "src", "source", "dest", "redirect",
               "image", "img", "load", "fetch", "site", "domain", "callback",
               "webhook", "feed", "host", "path", "proxy", "target"]

# 带内报错特征（很多 SSRF 尝试连接失败会回显）
ERROR_SIGNS = [
    r"Connection refused", r"Failed to connect", r"Name or service not known",
    r"getaddrinfo", r"couldn't connect to host", r"cURL error",
    r"UnknownHostException", r"No route to host", r"timed out",
]


class SSRFScanner(BaseScanner):
    name = "ssrf"
    passive = False

    def run(self):
        canary = self.config.canary
        log("INFO", f"SSRF 检测（canary={canary}，带外确认需自建 collaborator）...")
        targets = self.injection_targets(common_params=SSRF_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        canary = self.config.canary
        # 只对「看起来像 URL/主机」的参数或常见 SSRF 参数名注入
        probes = [f"http://{canary}/wvsssrf", f"https://{canary}/wvsssrf",
                  f"//{canary}/wvsssrf"]
        for probe in probes:
            test = dict(params)
            test[pname] = probe
            if method == "POST":
                r = self.post(url, data=test)
            else:
                r = self.get(build_url(url, test))
            if not r:
                continue
            body = r.text or ""
            # 带内提示：canary 出现在响应里，或返回连接类错误
            if canary in body:
                log("VULN", f"[SSRF-疑似] 参数: {pname}（响应回显 canary）")
                self.add("SSRF", "MEDIUM",
                         f"参数 '{pname}' 疑似 SSRF（响应回显了注入的外部地址）",
                         evidence=f"probe={probe} @ {url}", url=url,
                         confidence="疑似")
                return f"{pname}@{url}"
            for sign in ERROR_SIGNS:
                if re.search(sign, body, re.I):
                    log("VULN", f"[SSRF-疑似] 参数: {pname}（服务端连接错误）")
                    self.add("SSRF", "LOW",
                             f"参数 '{pname}' 可能触发服务端请求（返回连接错误，需带外确认）",
                             evidence=f"probe={probe} 触发 '{sign}' @ {url}",
                             url=url, confidence="疑似")
                    return f"{pname}@{url}"
        return None
