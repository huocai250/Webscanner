"""
集中式扫描配置
Author: 火柴 | GitHub: huocai250
v4.0 新增：统一用 dataclass 管理所有选项，替代到处传递的 **kwargs
"""
from dataclasses import dataclass, field
from urllib.parse import urlparse

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# 随机 User-Agent 池（--random-agent 时使用）
USER_AGENTS = [
    DEFAULT_UA,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


@dataclass
class ScanConfig:
    target: str

    # 网络行为
    timeout: float = 10.0
    threads: int = 10
    retries: int = 2
    verify_ssl: bool = False
    proxy: str | None = None
    user_agent: str = DEFAULT_UA
    random_agent: bool = False
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)

    # 频率控制（负责任扫描）
    delay: float = 0.0          # 每个请求后的固定延迟（秒）
    jitter: float = 0.0         # 附加 0..jitter 的随机抖动（秒）
    rate: float = 0.0           # 全局最大请求数/秒（0 = 不限制）

    # 爬虫
    crawl: bool = True
    max_urls: int = 100
    max_depth: int = 2

    # 作用域（安全护栏）：允许扫描的主机后缀列表，为空则默认锁定目标主机
    scope: list[str] = field(default_factory=list)

    # 模式
    passive: bool = False       # 被动模式：只做非侵入式检测

    # 字典
    wordlist_file: str | None = None
    subdomain_wordlist: str | None = None

    # OOB 探测用的 canary 域名（Log4Shell / SSRF / XXE 带外确认）
    # 需替换为你控制的 collaborator 域名后，越界回连才可被观测到
    canary: str = "oob.canary.example"

    # 插件目录（热加载自定义模块）
    plugins_dir: str | None = None

    # 额外模板目录（在内置 templates/ 之外追加 YAML 签名）
    templates_dir: str | None = None

    # 输出
    json_out: str | None = None
    html_out: str | None = None
    md_out: str | None = None
    csv_out: str | None = None
    log_out: str | None = None
    auto_report: bool = False   # v4: 默认不再自动保存，需显式开启

    # 跳过模块（模块 name 集合）
    skip: set = field(default_factory=set)

    def host(self) -> str:
        return urlparse(self.target).hostname or ""

    def normalized_target(self) -> str:
        t = self.target
        if not t.startswith(("http://", "https://")):
            t = "http://" + t
        return t

    def in_scope(self, url: str) -> bool:
        """判断某 URL 是否在允许的作用域内。"""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        allowed = self.scope or [self.host().lower()]
        for suffix in allowed:
            suffix = suffix.lower().lstrip("*.")
            if host == suffix or host.endswith("." + suffix):
                return True
        return False
