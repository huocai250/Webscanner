"""
[新增] 爬虫模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

自动爬取目标页面，发现更多参数和端点供其他模块扫描
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")

import re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.scanner import BaseScanner
from utils.http import extract_links, extract_forms, extract_all_urls



class Crawler(BaseScanner):
    def __init__(self, *args, max_pages: int = 50, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_pages  = max_pages
        self.visited    = set()
        self.found_urls = []   # 带参数的 URL
        self.found_forms = []  # 表单列表

    def run(self):
        _before = self.result.total()
        log.info(f"爬虫启动（最大 {self.max_pages} 页）...")
        queue   = deque([self.target])
        visited = set()

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            r = self.get(url)
            if not r or "text/html" not in r.headers.get("Content-Type", ""):
                continue

            log.info(f"  爬取: {url}")

            # 提取所有链接
            for link in extract_links(r.text, url):
                if link not in visited:
                    queue.append(link)

            # 收集带参数的 URL（去重）
            parsed = urlparse(url)
            if parsed.query and url not in self.found_urls:
                self.found_urls.append(url)
                log.info(f"  发现参数URL: {url[:80]}")
                self.result.add("爬虫发现", "INFO",
                                f"发现带参数页面: {url}", url=url)

            # 收集表单
            for form in extract_forms(r.text):
                action = form["action"] or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                form["source_url"] = url
                form["action"]     = action
                self.found_forms.append(form)
                log.info(f"  发现表单: {action} [{form['method']}] "
                         f"参数: {list(form['inputs'].keys())}")
                self.result.add("爬虫发现", "INFO",
                                f"发现表单: {action} 参数={list(form['inputs'].keys())}",
                                url=action)

        log.info(f"爬虫完成: 访问 {len(visited)} 页, "
                 f"发现 {len(self.found_urls)} 个参数URL, "
                 f"{len(self.found_forms)} 个表单")
        self._log_module_done("爬虫", _before)
