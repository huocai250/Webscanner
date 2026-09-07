"""
PHP 包装器 / LFI 向量检测模块（主动 / 检测导向）
Author: 火柴 | GitHub: huocai250

检测参数是否会经过 PHP 流包装器（php://filter、data://、expect://、phar://）。
这类向量常把普通 LFI 升级为源码读取甚至 RCE。此处**只检测是否被解析**（用
php://filter 的 base64 编码特征判断），不注入任何可执行代码、不读取敏感文件。
"""
import re
import base64
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 可能承载文件路径的参数
FILE_PARAMS = ["file", "page", "path", "template", "include", "doc", "document",
               "view", "content", "layout", "module", "lang", "read", "load"]


class PHPWrapperScanner(BaseScanner):
    name = "phpwrapper"
    passive = False

    def run(self):
        log("INFO", "PHP 包装器/LFI 向量检测（php://filter 编码特征）...")
        targets = self.injection_targets(FILE_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        # php://filter 把资源经 base64 输出；用一个已知资源探测编码是否发生
        # 使用 resource=index（常见入口），只观察是否返回 base64 块，不解码敏感内容
        probes = [
            "php://filter/convert.base64-encode/resource=index",
            "php://filter/read=convert.base64-encode/resource=index.php",
        ]
        for probe in probes:
            test = dict(params); test[pname] = probe
            r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
            if not r or not r.text:
                continue
            if self._looks_base64_blob(r.text):
                log("VULN", f"[PHP包装器] 参数 {pname} 解析 php://filter")
                self.add("文件包含", "HIGH",
                         f"参数 '{pname}' 经 PHP 流包装器处理（php://filter 返回 base64 编码内容），"
                         "存在源码读取/LFI 升级风险",
                         evidence=f"payload={probe} @ {url}", url=url, confidence="疑似")
                return f"{pname}@{url}"
        # data:// 包装器探测（返回我们提供的无害标记即说明被解析）
        marker = "WVSDATA123"
        data_probe = "data://text/plain;base64," + base64.b64encode(marker.encode()).decode()
        test = dict(params); test[pname] = data_probe
        r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
        if r and marker in (r.text or ""):
            log("VULN", f"[PHP包装器] 参数 {pname} 解析 data://")
            self.add("文件包含", "HIGH",
                     f"参数 '{pname}' 支持 data:// 包装器（回显了注入的无害数据），"
                     "若 allow_url_include 开启可导致 RCE",
                     evidence=f"data:// @ {url}", url=url, confidence="疑似")
            return f"{pname}@{url}"
        return None

    @staticmethod
    def _looks_base64_blob(text):
        # 找一段较长的、疑似 base64 的连续块（php://filter 典型输出）
        for m in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', text):
            chunk = m.group(0)
            try:
                dec = base64.b64decode(chunk[: (len(chunk) // 4) * 4], validate=True)
                # 解码结果含 PHP/HTML 源码特征则更可信（不外泄内容，只判定）
                if b"<?php" in dec or b"<html" in dec or b"function" in dec:
                    return True
            except Exception:
                continue
        return False
