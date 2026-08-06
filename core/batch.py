"""
批量 / 异步多目标扫描
Author: 火柴 | GitHub: huocai250

用 asyncio 并发调度多个目标的扫描（每个目标的扫描内部仍是线程池引擎，
通过 run_in_executor 包装，实现「多目标并发、互不阻塞」）。
不依赖 aiohttp，仅用标准库。
"""
import copy
import asyncio
from concurrent.futures import ThreadPoolExecutor

from core.config import ScanConfig
from core.engine import run_scan
from core.colors import log, Colors


def load_targets(path: str) -> list:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f
                if ln.strip() and not ln.strip().startswith("#")]


def _cfg_for(base_cfg: ScanConfig, target: str) -> ScanConfig:
    cfg = copy.copy(base_cfg)
    cfg.target = target
    # 作用域默认锁定各自目标主机
    if not base_cfg.scope:
        cfg.scope = []
    return cfg


async def _run_all(base_cfg: ScanConfig, targets: list, concurrency: int) -> dict:
    results = {}
    sem = asyncio.Semaphore(max(1, concurrency))
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=max(1, concurrency))

    async def worker(target):
        async with sem:
            cfg = _cfg_for(base_cfg, target)
            log("INFO", f"{Colors.CYAN}[批量] 开始: {target}{Colors.RESET}")
            # 并发多目标时关闭逐模块的花哨输出，避免交错
            res = await loop.run_in_executor(
                executor, lambda: run_scan(cfg, verbose=False))
            results[target] = res
            log("INFO", f"{Colors.GREEN}[批量] 完成: {target} "
                        f"（{len(res.findings)} 项, 风险 {res.risk_score()}）{Colors.RESET}")

    await asyncio.gather(*(worker(t) for t in targets))
    executor.shutdown(wait=True)
    return results


def run_batch(base_cfg: ScanConfig, targets: list, concurrency: int = 3) -> dict:
    """并发扫描多个目标，返回 {target: ScanResult}。"""
    log("INFO", f"批量扫描 {len(targets)} 个目标（并发 {concurrency}）...")
    return asyncio.run(_run_all(base_cfg, targets, concurrency))
