"""
线程安全的全局速率限制器
Author: 火柴 | GitHub: huocai250
v4.0 新增：负责任扫描 —— 限制对目标的请求速率，降低目标负载/避免被封
"""
import time
import random
import threading


class RateLimiter:
    """令牌桶式限速：保证全局每秒不超过 rate 个请求。"""

    def __init__(self, rate: float = 0.0):
        self.min_interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.min_interval
        if sleep_for > 0:
            time.sleep(sleep_for)


def polite_delay(delay: float, jitter: float):
    """每请求礼貌延迟 + 随机抖动。"""
    total = 0.0
    if delay > 0:
        total += delay
    if jitter > 0:
        total += random.uniform(0, jitter)
    if total > 0:
        time.sleep(total)
