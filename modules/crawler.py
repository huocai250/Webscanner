"""
轻量爬虫模块（发现 URL 与注入点）
Author: 火柴 | GitHub: huocai250
v4.0 新增：BFS 爬取同源页面，收集带参数的 URL 与表单，
          供 SQLi/XSS/LFI/重定向等模块测试真实攻击面。
"""
from collections import deque
from core.scanner import BaseScanner
from core.colors import log
from utils.http import extract_links, extract_forms, url_params, strip_query


class Crawler(BaseScanner):
    name = "crawler"
    passive = True   # 只是抓取页面，非侵入式

    def run(self):
        cfg = self.config
        # 始终把种子 URL 自身登记为注入点（若带参数）
        self._register_url(self.config.normalized_target())

        if not cfg.crawl:
            log("SKIP", "爬虫已禁用，仅测试种子 URL")
            self._register_common_guess()
            return

        log("INFO", f"爬取站点 (最多 {cfg.max_urls} 个页面, 深度 {cfg.max_depth})...")
        seed = self.config.normalized_target()
        queue = deque([(seed, 0)])
        visited = set()
        page_count = 0

        while queue and page_count < cfg.max_urls:
            url, depth = queue.popleft()
            norm = url.split("#")[0]
            if norm in visited:
                continue
            visited.add(norm)

            r = self.get(norm)
            if not r or "text/html" not in r.headers.get("Content-Type", ""):
                continue
            page_count += 1

            self._register_url(norm)
            self._register_forms(r.text, norm)

            if depth < cfg.max_depth:
                for link in extract_links(r.text, norm):
                    if link not in visited:
                        queue.append((link, depth + 1))

        log("OK", f"爬取完成：{page_count} 个页面，"
                  f"{len(self.ctx.injection_points)} 个注入点")
        self.ctx.result.add("信息收集", "INFO",
                            f"爬虫发现 {len(self.ctx.injection_points)} 个可测试注入点",
                            confidence="信息")
        self._register_common_guess()

    def _register_url(self, url: str):
        params = url_params(url)
        if params:
            self.ctx.add_injection_point(strip_query(url), "GET", params, "url")

    def _register_forms(self, html: str, base: str):
        for form in extract_forms(html, base):
            action = form["action"] or base
            if form["inputs"]:
                self.ctx.add_injection_point(action, form["method"],
                                             form["inputs"], "form")

    def _register_common_guess(self):
        """当爬虫没发现任何带参 URL 时，退回到常见参数名猜测。"""
        if any(ip["source"] != "guess" for ip in self.ctx.injection_points):
            return
        seed = strip_query(self.config.normalized_target())
        self.ctx.add_injection_point(seed, "GET", {"id": "1"}, "guess")
