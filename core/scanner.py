"""
基础扫描器类 — 所有模块继承此类
Author: 火柴 | GitHub: huocai250

修复:
- 添加请求重试机制
- 添加连接池复用
- 统一 headers 合并
- 超时异常分类处理
"""
import time
from typing import Optional, Dict
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.result import ScanResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _make_session(proxy: str = None) -> requests.Session:
    session = requests.Session()
    session.verify = False
    # 重试策略：连接失败/超时最多重试2次，间隔递增
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": DEFAULT_UA})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


class BaseScanner:
    def __init__(
        self,
        target: str,
        result: ScanResult,
        timeout: int = 10,
        threads: int = 10,
        cookies: Dict = None,
        headers: Dict = None,
        proxy: str = None,
    ):
        self.target  = target.rstrip("/")
        self.result  = result
        self.timeout = timeout
        self.threads = threads

        self.session = _make_session(proxy)
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

    # ── 核心请求方法 ──────────────────────────────────────────

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        try:
            return self.session.get(url, **kwargs)
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def post(self, url: str, data=None, json_data=None,
             extra_headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """
        extra_headers: 本次请求额外附加的 headers（不修改 session）
        json_data: 发送 JSON body（避免与内置 json 模块命名冲突）
        """
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        if extra_headers:
            # 合并而不污染 session
            merged = {**dict(self.session.headers), **extra_headers}
            kwargs["headers"] = merged
        try:
            return self.session.post(url, data=data, json=json_data, **kwargs)
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """发送任意 HTTP 方法"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        try:
            return self.session.request(method, url, **kwargs)
        except Exception:
            return None

    # ── 工具方法 ─────────────────────────────────────────────

    def url(self, path: str) -> str:
        return f"{self.target}/{path.lstrip('/')}"

    def run(self):
        raise NotImplementedError
