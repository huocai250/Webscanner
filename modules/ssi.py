"""
SSI（服务端包含）注入检测模块（主动 / 无害探针）
Author: 火柴 | GitHub: huocai250

注入 SSI 指令探针，若响应中出现被解析的结果（如 echo 变量被展开），则存在
SSI 注入。探针使用无害的算术/变量回显，不执行任何系统命令。
"""
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 无害探针：只用 printenv 的服务器变量特征（要求多个专有变量名同时出现，避免误报）
MARKER = "wvsSSI"
PROBES = [
    ('<!--#printenv -->',
     ["DOCUMENT_ROOT", "SERVER_SOFTWARE", "SERVER_NAME", "GATEWAY_INTERFACE",
      "SCRIPT_FILENAME", "REQUEST_METHOD"]),
]


def _hits(body, signs):
    return sum(1 for s in signs if s in body)

SSI_PARAMS = ["q", "search", "name", "page", "input", "comment", "msg", "text"]


class SSIScanner(BaseScanner):
    name = "ssi"
    passive = False

    def run(self):
        log("INFO", "SSI 注入检测（无害回显探针，并发）...")
        targets = self.injection_targets(SSI_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        for probe, signs in PROBES:
            test = dict(params); test[pname] = probe
            r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
            if not r or not r.text:
                continue
            body = r.text
            # 探针未被原样回显，但出现了多个服务器环境变量特征 => SSI 被解析
            if probe not in body and _hits(body, signs) >= 2:
                log("VULN", f"[SSI注入] 参数 {pname}")
                self.add("SSI 注入", "HIGH",
                         f"参数 '{pname}' 疑似 SSI 注入（SSI 指令被服务端解析，回显环境变量）",
                         evidence=f"probe={probe[:30]} @ {url}", url=url,
                         confidence="疑似")
                return f"{pname}@{url}"
        return None
