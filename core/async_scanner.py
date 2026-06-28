"""
异步多目标扫描引擎 — WebVulnScanner v7.0
Author: 火柴 | GitHub: huocai250

[新增] asyncio 并发扫描多个目标
  - 每个目标独立协程，互不阻塞
  - 实时进度回调
  - 结果聚合
"""
import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Callable, Dict, Optional
from core.result import ScanResult

log = logging.getLogger("webscan")


class AsyncScanEngine:
    """
    [新增] 异步多目标扫描引擎
    
    扫描模块本身是同步的（requests），所以用线程池 + asyncio 实现并发：
    - 每个目标在独立线程中运行完整扫描
    - asyncio 负责调度和结果收集
    - 支持最大并发数限制
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        progress_cb: Optional[Callable] = None,
    ):
        self.max_concurrent = max_concurrent
        self.progress_cb    = progress_cb
        self._results: Dict[str, ScanResult] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=max_concurrent,
            thread_name_prefix="webscan_async"
        )

    async def scan_all(
        self,
        targets: List[str],
        scan_fn: Callable,          # 同步扫描函数 scan_fn(target) -> ScanResult
    ) -> Dict[str, ScanResult]:
        """
        并发扫描所有目标
        scan_fn: 接收 target 字符串，返回 ScanResult 的同步函数
        """
        log.info(f"[异步引擎] 开始扫描 {len(targets)} 个目标，"
                 f"最大并发: {self.max_concurrent}")

        semaphore = asyncio.Semaphore(self.max_concurrent)
        loop      = asyncio.get_event_loop()
        tasks     = []

        for target in targets:
            task = asyncio.ensure_future(
                self._scan_one(target, scan_fn, semaphore, loop)
            )
            tasks.append(task)

        # 等待所有任务完成，实时收集结果
        done_count = 0
        total      = len(tasks)

        for coro in asyncio.as_completed(tasks):
            target, result = await coro
            done_count += 1
            if result:
                self._results[target] = result
            if self.progress_cb:
                self.progress_cb(target, done_count, total, result)
            log.info(f"[异步引擎] 进度: {done_count}/{total} — {target}")

        log.info(f"[异步引擎] 全部完成，共 {len(self._results)} 个结果")
        return self._results

    async def _scan_one(
        self,
        target:    str,
        scan_fn:   Callable,
        semaphore: asyncio.Semaphore,
        loop:      asyncio.AbstractEventLoop,
    ):
        """单目标扫描协程"""
        async with semaphore:
            log.info(f"[异步引擎] 开始: {target}")
            t0 = time.monotonic()
            try:
                # 在线程池中运行同步扫描函数
                result = await loop.run_in_executor(
                    self._executor, scan_fn, target
                )
                elapsed = time.monotonic() - t0
                log.info(f"[异步引擎] 完成: {target} ({elapsed:.1f}s)")
                return target, result
            except Exception as e:
                log.error(f"[异步引擎] 失败: {target}: {e}")
                return target, None

    def run_sync(
        self,
        targets:  List[str],
        scan_fn:  Callable,
    ) -> Dict[str, ScanResult]:
        """
        同步入口：在新 event loop 中运行异步扫描
        用于从同步代码（main.py）调用
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                self.scan_all(targets, scan_fn)
            )
        finally:
            loop.close()
            self._executor.shutdown(wait=False)

    def shutdown(self):
        self._executor.shutdown(wait=True)
