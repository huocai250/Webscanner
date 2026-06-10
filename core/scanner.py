"""
基础扫描器类 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[优化] 集成速率限制、重试机制、统一异常处理
       [新增] progress 进度回调
       [新增] validate_url 工具方法
       [优化] 命名更规范
"""
import time
import logging
from typing import Optional, Dict, Callable
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.result      import ScanResult
from core.rate_limiter import RateLimiter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

log = logging.getLogger("webscan")


def build_session(
    proxy:       str = None,
    max_retries: int = 2,
    user_agent:  str = None,
) -> requests.Session:
    """
    [优化] 统一 Session 工厂：连接池 + 重试策略
    """
    session = requests.Session()
    session.verify = False

    # [新增] 重试策略：状态码5xx 自动重试，指数退避
    retry_strategy = Retry(
        total              = max_retries,
        backoff_factor     = 0.5,
        status_forcelist   = [500, 502, 503, 504],
        allowed_methods    = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"],
        raise_on_status    = False,
    )
    adapter = HTTPAdapter(
        max_retries    = retry_strategy,
        pool_connections = 20,
        pool_maxsize     = 20,
    )
    session.mount("http://",  adapter)
    session.mount("https://", adapter)

    session.headers.update({
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    return session


def validate_url(url: str) -> str:
    """
    [新增] URL 校验与规范化
    - 自动补全 http:// 前缀
    - 移除末尾 /
    """
    if not url:
        raise ValueError("目标 URL 不能为空")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


class BaseScanner:
    """
    [优化] 所有扫描模块的基类
    封装: HTTP请求 / 速率限制 / 重试 / 日志 / URL工具
    """

    def __init__(
        self,
        target:       str,
        result:       ScanResult,
        timeout:      int      = 10,
        threads:      int      = 10,
        cookies:      Dict     = None,
        headers:      Dict     = None,
        proxy:        str      = None,
        rate_limiter: RateLimiter = None,
        max_retries:  int      = 2,
        user_agent:   str      = None,
        exploit_mode: bool     = False,
        progress_cb:  Callable = None,  # [新增] 进度回调
    ):
        self.target       = validate_url(target)
        self.result       = result
        self.timeout      = timeout
        self.threads      = threads
        self.exploit_mode = exploit_mode
        self.progress_cb  = progress_cb
        self.rate_limiter = rate_limiter or RateLimiter(0)

        self.session = build_session(proxy, max_retries, user_agent)
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

    # ── HTTP 请求封装 ─────────────────────────────────────────

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """[优化] GET 请求，含速率限制 + 统一异常处理"""
        self.rate_limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify",  False)
        try:
            resp = self.session.get(url, **kwargs)
            log.debug(f"GET {url} → {resp.status_code}")
            return resp
        except requests.exceptions.Timeout:
            log.debug(f"GET {url} 超时")
            return None
        except requests.exceptions.ConnectionError as e:
            log.debug(f"GET {url} 连接失败: {e}")
            return None
        except Exception as e:
            log.debug(f"GET {url} 异常: {type(e).__name__}: {e}")
            return None

    def post(
        self,
        url:           str,
        data           = None,
        json_data      = None,
        extra_headers: Dict = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        """[优化] POST 请求，extra_headers 不污染 session"""
        self.rate_limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify",  False)
        if extra_headers:
            kwargs["headers"] = {**dict(self.session.headers), **extra_headers}
        try:
            resp = self.session.post(url, data=data, json=json_data, **kwargs)
            log.debug(f"POST {url} → {resp.status_code}")
            return resp
        except requests.exceptions.Timeout:
            log.debug(f"POST {url} 超时")
            return None
        except Exception as e:
            log.debug(f"POST {url} 异常: {type(e).__name__}: {e}")
            return None

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """[新增] 任意 HTTP 方法"""
        self.rate_limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify",  False)
        try:
            resp = self.session.request(method, url, **kwargs)
            log.debug(f"{method} {url} → {resp.status_code}")
            return resp
        except Exception as e:
            log.debug(f"{method} {url} 异常: {type(e).__name__}: {e}")
            return None

    # ── URL 工具 ──────────────────────────────────────────────

    def build_url(self, path: str) -> str:
        """[优化] 重命名 url() → build_url()，语义更清晰"""
        return f"{self.target}/{path.lstrip('/')}"

    # 向后兼容别名
    def url(self, path: str) -> str:
        return self.build_url(path)

    def same_origin(self, url: str) -> bool:
        """[新增] 判断 URL 是否与目标同源"""
        return urlparse(url).netloc == urlparse(self.target).netloc

    # ── 进度上报 ──────────────────────────────────────────────

    def report_progress(self, message: str):
        """[新增] 模块进度回调"""
        if self.progress_cb:
            self.progress_cb(message)

    def run(self):
        raise NotImplementedError
