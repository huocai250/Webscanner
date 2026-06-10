"""
速率限制模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[新增] 令牌桶算法实现速率限制，防止扫描时被封 IP
"""
import time
import threading


class RateLimiter:
    """
    [新增] 令牌桶速率限制器
    - min_interval: 两次请求之间的最小间隔（秒），0 = 不限制
    - 线程安全
    """
    def __init__(self, min_interval: float = 0.0):
        self.min_interval  = min_interval
        self._last_request = 0.0
        self._lock         = threading.Lock()

    def wait(self):
        """在发起请求前调用，自动等待至满足速率限制"""
        if self.min_interval <= 0:
            return
        with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last_request
            wait_s  = self.min_interval - elapsed
            if wait_s > 0:
                time.sleep(wait_s)
            self._last_request = time.monotonic()

    def set_interval(self, interval: float):
        self.min_interval = interval
