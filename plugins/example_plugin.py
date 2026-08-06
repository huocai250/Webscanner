"""
示例插件：检测 .DS_Store / Thumbs.db 泄露
Author: 火柴

这是一个演示插件，展示如何编写自定义扫描模块。
把任意继承 BaseScanner 的类放进 plugins/ 目录即可被自动加载。
运行： python main.py https://example.com --plugins plugins
"""
from core.scanner import BaseScanner
from core.colors import log


class DSStoreScanner(BaseScanner):
    name = "ds_store"          # 唯一名称（可用 --skip ds_store 跳过）
    passive = True             # 非侵入式，被动模式下也会运行

    CHECKS = [
        (".DS_Store", b"\x00\x00\x00\x01Bud1", "macOS .DS_Store 泄露（可能暴露目录结构）"),
        ("Thumbs.db", b"", "Windows Thumbs.db 泄露"),
    ]

    def run(self):
        log("INFO", "[插件] 检测 .DS_Store / Thumbs.db 泄露...")
        for path, magic, desc in self.CHECKS:
            r = self.get(self.url(path))
            if not r or r.status_code != 200:
                continue
            content = r.content or b""
            if magic and content.startswith(magic):
                self.add("敏感信息泄露", "LOW", desc, url=r.url)
                log("VULN", f"[插件] {desc}")
            elif not magic and content:
                self.add("敏感信息泄露", "LOW", desc, url=r.url, confidence="疑似")
