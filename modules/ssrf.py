"""
SSRF（服务端请求伪造）检测模块（主动 / 检测导向）
Author: 火柴 | GitHub: huocai250

向**可能触发服务端请求的参数**注入你控制的 canary URL，通过服务端连接行为
（连接错误特征 / 带外回连）判断是否存在 SSRF。

v9 优化：只测试「疑似 URL 汇聚点」的参数（参数名属于 URL 类，或原值本身像
URL/主机），并要求「服务端确实尝试了请求」的证据（连接错误特征），不再把
「参数回显了 URL」这种单纯反射误判为 SSRF —— 显著降低误报。

安全边界：**只检测**服务端是否会向外部发起请求；不读云元数据 / 不探内网 /
不读文件。请将 canary 配置为你自己的 collaborator。
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

SSRF_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "redirect", "redirect_uri",
    "image", "img", "load", "fetch", "site", "domain", "callback", "webhook",
    "feed", "host", "proxy", "target", "u", "path", "file", "page", "open",
    "next", "data", "reference", "ref", "continue", "return", "returnurl",
}

# 服务端「尝试了请求但失败/异常」的特征（强 SSRF 指示）
CONNECT_SIGNS = [
    r"Connection refused", r"Failed to connect", r"Name or service not known",
    r"getaddrinfo", r"couldn'?t connect to host", r"cURL error \d+",
    r"UnknownHostException", r"No route to host", r"Connection timed out",
    r"nodename nor servname", r"Could not resolve host", r"HTTPConnectionPool",
    r"ECONNREFUSED", r"EHOSTUNREACH", r"upstream connect error",
]


def _looks_url(val):
    if not val:
        return False
    v = str(val).lower()
    return (v.startswith(("http://", "https://", "//", "ftp://"))
            or bool(re.match(r'^[a-z0-9.\-]+\.[a-z]{2,}(/|$)', v)))


class SSRFScanner(BaseScanner):
    name = "ssrf"
    passive = False

    def run(self):
        canary = self.config.canary
        log("INFO", f"SSRF 检测（canary={canary}；仅测 URL 汇聚参数）...")
        targets = self._targets()
        if not targets:
            log("INFO", "  未发现疑似 URL 参数")
            return
        self.map(self._test, targets)

    def _targets(self):
        """只选取参数名像 URL 或原值像 URL 的注入点，降低误报。"""
        out, seen = [], set()
        for ip in self.ctx.injection_points:
            for pname, pval in ip["params"].items():
                if pname.lower() in SSRF_PARAM_NAMES or _looks_url(pval):
                    key = (ip["url"], ip["method"], pname)
                    if key not in seen:
                        seen.add(key)
                        out.append((ip["url"], ip["method"], dict(ip["params"]), pname))
        if not out:
            for pname in ("url", "uri", "target", "redirect", "image", "fetch"):
                out.append((self.target, "GET", {pname: "http://example.com"}, pname))
        return out

    def _test(self, target):
        url, method, params, pname = target
        canary = self.config.canary
        for probe in (f"http://{canary}/wvsssrf", f"https://{canary}/wvsssrf"):
            test = dict(params); test[pname] = probe
            if method == "POST":
                r = self.post(url, data=test)
            else:
                r = self.get(build_url(url, test))
            if not r:
                continue
            body = r.text or ""
            for sign in CONNECT_SIGNS:
                if re.search(sign, body, re.I):
                    log("VULN", f"[SSRF-疑似] 参数 {pname}（服务端连接特征）")
                    self.add("SSRF", "MEDIUM",
                             f"参数 '{pname}' 疑似 SSRF（服务端尝试请求外部地址并返回连接错误）",
                             evidence=f"probe={probe} 触发 '{sign}' @ {url}",
                             url=url, confidence="疑似")
                    return f"{pname}@{url}"
            if canary in body and pname.lower() in SSRF_PARAM_NAMES:
                self.add("SSRF", "LOW",
                         f"URL 参数 '{pname}' 回显了注入地址（需带外 collaborator 确认是否真正发起请求）",
                         evidence=f"probe={probe} @ {url}", url=url, confidence="信息")
                return f"{pname}@{url}"
        return None
