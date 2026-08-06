"""
基础扫描器类（所有模块继承此类）
Author: 火柴 | GitHub: huocai250

v4.0 改进：
  - 统一 ScanContext 共享会话 / 限速器 / 基线缓存 / 已发现注入点
  - 每个请求自动：作用域校验、限速、礼貌延迟、失败重试
  - 提供 map() 并发助手，供各模块并行测试 payload
  - 基线响应缓存，避免重复抓取首页
"""
import random
import threading
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional

from core.config import ScanConfig, USER_AGENTS
from core.result import ScanResult
from core.colors import log
from utils.ratelimit import RateLimiter, polite_delay

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_session(cfg: ScanConfig) -> requests.Session:
    session = requests.Session()
    session.verify = cfg.verify_ssl
    session.headers.update({"User-Agent": cfg.user_agent})
    if cfg.cookies:
        session.cookies.update(cfg.cookies)
    if cfg.headers:
        session.headers.update(cfg.headers)
    if cfg.proxy:
        session.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    # 连接池调优
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=cfg.threads * 2,
        pool_maxsize=cfg.threads * 2,
        max_retries=0,               # 重试逻辑自己处理
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


class ScanContext:
    """在所有模块间共享的运行时上下文。"""

    def __init__(self, config: ScanConfig, result: ScanResult):
        self.config = config
        self.result = result
        self.session = build_session(config)
        self.limiter = RateLimiter(config.rate)
        self._baseline: dict = {}
        self._baseline_lock = threading.Lock()
        self._scope_warned = set()

        # 爬虫填充、其它模块消费的注入点列表
        # 每项：{"url","method","params"(dict),"source"}
        self.injection_points: List[dict] = []
        self._ip_lock = threading.Lock()
        self._ip_seen = set()

        # 指纹识别结果（Fingerprinter 写入，CMSScanner 等消费）
        # 每项：{"name","category","version"}
        self.fingerprints: List[dict] = []
        self._fp_lock = threading.Lock()
        self._fp_seen = set()

    def add_fingerprint(self, name: str, category: str, version: str = ""):
        key = (name, category)
        with self._fp_lock:
            if key in self._fp_seen:
                return
            self._fp_seen.add(key)
            self.fingerprints.append(
                {"name": name, "category": category, "version": version})

    def tech_names(self) -> set:
        with self._fp_lock:
            return {f["name"].lower() for f in self.fingerprints}

    def add_injection_point(self, url: str, method: str, params: dict, source: str):
        key = (url, method.upper(), tuple(sorted(params.keys())))
        with self._ip_lock:
            if key in self._ip_seen:
                return
            self._ip_seen.add(key)
            self.injection_points.append({
                "url": url, "method": method.upper(),
                "params": dict(params), "source": source,
            })


class BaseScanner:
    name = "base"
    # passive=True 的模块在被动模式下仍会运行（非侵入式）
    passive = False

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.config = ctx.config
        self.result = ctx.result
        self.session = ctx.session
        self.target = self.config.normalized_target().rstrip("/")
        self.timeout = self.config.timeout
        self.threads = self.config.threads

    # ---- 网络层 ------------------------------------------------------
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """带作用域校验、限速、礼貌延迟与重试的统一请求入口。"""
        if not self.config.in_scope(url):
            host = url.split("/")[2] if "://" in url else url
            if host not in self.ctx._scope_warned:
                self.ctx._scope_warned.add(host)
                log("SKIP", f"跳过作用域外目标: {host}")
            return None

        kwargs.setdefault("timeout", self.timeout)
        if self.config.random_agent:
            hdrs = dict(kwargs.get("headers") or {})
            hdrs.setdefault("User-Agent", random.choice(USER_AGENTS))
            kwargs["headers"] = hdrs

        attempts = self.config.retries + 1
        for i in range(attempts):
            self.ctx.limiter.wait()
            try:
                resp = self.session.request(method, url, **kwargs)
                self.result.incr_requests()
                polite_delay(self.config.delay, self.config.jitter)
                return resp
            except (requests.ConnectionError, requests.Timeout):
                if i < attempts - 1:
                    # 指数退避
                    import time
                    time.sleep(0.3 * (2 ** i))
                    continue
                return None
            except Exception:
                return None
        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, data=data, json=json, **kwargs)

    # ---- 助手 --------------------------------------------------------
    def url(self, path: str) -> str:
        return f"{self.target}/{path.lstrip('/')}"

    def baseline(self, url: str = None) -> Optional[requests.Response]:
        """获取（并缓存）某 URL 的基线响应，避免重复抓取。"""
        url = url or self.target
        with self.ctx._baseline_lock:
            if url in self.ctx._baseline:
                return self.ctx._baseline[url]
        resp = self.get(url)
        with self.ctx._baseline_lock:
            self.ctx._baseline[url] = resp
        return resp

    def map(self, fn: Callable, items: Iterable, workers: int = None) -> List:
        """并发对 items 执行 fn，返回非 None 结果列表。"""
        items = list(items)
        if not items:
            return []
        workers = workers or self.threads
        results = []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futures = [ex.submit(fn, it) for it in items]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res is not None:
                    results.append(res)
        return results

    def add(self, category, severity, detail, evidence="", url="", confidence="确认"):
        return self.result.add(category, severity, detail, evidence, url, confidence)

    def injection_targets(self, common_params: list = None) -> list:
        """
        构造 (url, method, params, param_name) 测试目标列表：
          - 爬虫发现的每个注入点的每个参数
          - 若未发现真实参数，则在种子 URL 上退回测试 common_params
        """
        targets = []
        real_found = False
        for ip in self.ctx.injection_points:
            if ip["source"] in ("url", "form"):
                real_found = True
            for pname in ip["params"]:
                targets.append((ip["url"], ip["method"], dict(ip["params"]), pname))

        if not real_found and common_params:
            seed = self.target
            for pname in common_params:
                targets.append((seed, "GET", {pname: "1"}, pname))
        return targets

    def run(self):
        raise NotImplementedError
