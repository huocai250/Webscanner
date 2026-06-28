"""
敏感信息泄露检测模块 — WebVulnScanner v7.0
Author: 火柴 | GitHub: huocai250

修复:
- [核心修复] 响应为 HTML 页面时直接跳过（软404首要特征）
- [修复] 软404采样改为3次取中位数，对抗动态内容长度波动
- [修复] 相似度阈值改为比例判断（90%相似 = 软404）
- [修复] 内容特征验证更严格，要求特征必须在非HTML区域出现
- [修复] 检查 Content-Type 头，config文件不该是 text/html
"""
import re
import logging
from typing import List, Tuple, Optional
from core.scanner import BaseScanner

log = logging.getLogger("webscan")

# ── 敏感信息正则模式 ──────────────────────────────────────────
PATTERNS = {
    "AWS Access Key":      (r'AKIA[0-9A-Z]{16}',                             "CRITICAL"),
    "AWS Secret Key":      (r'(?i)aws[_\-\s]?secret[_\-\s]?key\s*[=:]\s*\S{20,}', "CRITICAL"),
    "Private Key":         (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',  "CRITICAL"),
    "Password in Source":  (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "HIGH"),
    "Database URL":        (r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\'<>]+', "HIGH"),
    "API Key":             (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}', "HIGH"),
    "JWT Token":           (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "HIGH"),
    "Google API Key":      (r'AIza[0-9A-Za-z\-_]{35}',                      "HIGH"),
    "Stripe Secret Key":   (r'sk_live_[0-9a-zA-Z]{24}',                     "CRITICAL"),
    "GitHub Token":        (r'ghp_[0-9A-Za-z]{36}',                         "CRITICAL"),
    "Email Address":       (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', "LOW"),
    "Internal IP":         (r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b', "MEDIUM"),
    "Phone (CN)":          (r'\b1[3-9]\d{9}\b',                             "LOW"),
    "Chinese ID Card":     (r'\b\d{17}[\dXx]\b',                            "HIGH"),
}

# ── 敏感文件检测规则 ──────────────────────────────────────────
# 格式: (路径, 严重级别, 描述, 内容验证特征列表)
# 内容验证：至少匹配一个特征，且响应必须不是 HTML 页面
EXPOSED_FILES: List[Tuple] = [
    (".git/HEAD",
     "CRITICAL", ".git 目录暴露，可导致源码泄露",
     # git HEAD 文件固定格式
     [r"^ref:\s+refs/", r"^[0-9a-f]{40}$"]),

    (".git/config",
     "CRITICAL", ".git/config 暴露，含仓库配置",
     [r"\[core\]", r"\[remote\s+", r"repositoryformatversion\s*="]),

    (".env",
     "CRITICAL", ".env 配置文件暴露，含密钥/数据库凭据",
     # .env 格式：KEY=VALUE，必须有多个这样的行
     [r"^[A-Z_]{2,}\s*=", r"DB_HOST\s*=", r"APP_KEY\s*=",
      r"SECRET\s*=", r"PASSWORD\s*=", r"TOKEN\s*="]),

    (".env.local",
     "CRITICAL", ".env.local 文件暴露",
     [r"^[A-Z_]{2,}\s*=", r"DB_|APP_KEY|SECRET|PASSWORD"]),

    (".env.production",
     "CRITICAL", ".env.production 文件暴露",
     [r"^[A-Z_]{2,}\s*=", r"DB_|APP_KEY|SECRET|PASSWORD"]),

    ("phpinfo.php",
     "HIGH", "phpinfo 页面暴露，泄露服务器配置",
     # phpinfo 特有内容
     [r"PHP Version\s+\d+\.\d+", r"phpinfo\(\)", r"PHP License",
      r"Configure Command", r"php\.ini"]),

    (".htpasswd",
     "CRITICAL", ".htpasswd 暴露，含加密密码",
     # htpasswd 格式：user:hash — hash 必须是特定格式
     [r":\$apr1\$", r":\{SHA\}", r":\$2[aby]\$",
      r"^[\w.\-]+:\$"]),

    ("web.config",
     "HIGH", "web.config 暴露，可能含密钥",
     # XML 配置文件格式
     [r"<configuration>", r"<connectionStrings>",
      r"<appSettings>", r"<system\.web>"]),

    ("composer.json",
     "LOW", "composer.json 暴露，泄露依赖信息",
     [r'"require"\s*:', r'"name"\s*:\s*"[\w/\-]+"']),

    ("package.json",
     "LOW", "package.json 暴露，泄露依赖信息",
     [r'"dependencies"\s*:', r'"scripts"\s*:',
      r'"name"\s*:\s*"[\w\-@/]+"']),

    ("wp-config.php.bak",
     "CRITICAL", "WordPress 配置备份文件暴露",
     [r"DB_NAME", r"DB_USER", r"DB_PASSWORD",
      r"table_prefix\s*=", r"AUTH_KEY"]),

    ("backup.sql",
     "CRITICAL", "数据库备份文件暴露",
     # SQL dump 特有内容
     [r"INSERT INTO\s+`?\w+`?", r"CREATE TABLE\s+`?\w+`?",
      r"-- MySQL dump", r"-- PostgreSQL database dump",
      r"DROP TABLE IF EXISTS"]),

    ("dump.sql",
     "CRITICAL", "SQL dump 文件暴露",
     [r"INSERT INTO\s+`?\w+`?", r"CREATE TABLE\s+`?\w+`?",
      r"-- MySQL dump", r"DROP TABLE"]),

    (".bash_history",
     "HIGH", ".bash_history 暴露，含命令历史",
     # 命令历史：每行都是 shell 命令
     [r"^\s*(sudo|ssh|mysql|wget|curl|git|rm|cp|mv)\s+",
      r"^\s*cd\s+/", r"^\s*ls\s+"]),

    ("server-status",
     "MEDIUM", "Apache server-status 暴露",
     [r"Apache Server Status", r"Server Version:",
      r"Scoreboard Key:"]),

    ("actuator/env",
     "HIGH", "Spring Boot Actuator env 端点暴露",
     [r"activeProfiles", r"propertySources",
      r"systemEnvironment", r"applicationConfig"]),

    ("actuator/mappings",
     "HIGH", "Spring Boot Actuator mappings 暴露",
     [r"dispatcherServlets", r"requestMappingHandlerMapping",
      r"\"handler\":", r"\"predicate\":"]),

    ("actuator/heapdump",
     "CRITICAL", "Spring Boot heapdump 可能含敏感内存数据",
     # heapdump 是二进制文件
     [r"JAVA PROFILE", r"HPROF BINARY"]),
]

# HTML 页面特征 —— 命中这些说明是软404，不是真实文件
HTML_SIGNATURES = [
    r"<!DOCTYPE\s+html",
    r"<html[\s>]",
    r"<head>",
    r"<meta\s+charset",
    r"<title>",
    r"<body[\s>]",
]

# 通用软404文字特征
SOFT_404_WORDS = [
    "404", "not found", "page not found", "找不到", "页面不存在",
    "does not exist", "no encontrado", "introuvable", "error 404",
]


class SensitiveInfoScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._soft404_body  = ""
        self._soft404_len   = 0
        self._soft404_ctype = ""

    # ── 采样软404基准 ─────────────────────────────────────────

    def _sample_soft404(self) -> None:
        """
        [修复] 采样3次取中位数，对抗动态页面长度波动
        同时记录 Content-Type 作为辅助判断
        """
        lengths = []
        bodies  = []
        random_paths = [
            "__ws_nx_ref_aaa_11111__",
            "__ws_nx_ref_bbb_22222__",
            "__ws_nx_ref_ccc_33333__",
        ]
        for rp in random_paths:
            r = self.get(self.build_url(rp))
            if r:
                lengths.append(len(r.text))
                bodies.append(r.text)
                self._soft404_ctype = r.headers.get("Content-Type", "")

        if lengths:
            lengths.sort()
            mid_idx = len(lengths) // 2
            self._soft404_len  = lengths[mid_idx]   # 中位数长度
            self._soft404_body = bodies[mid_idx]
            log.info(f"软404基准: {self._soft404_len}b, "
                     f"Content-Type: {self._soft404_ctype[:40]}")

    # ── 主流程 ────────────────────────────────────────────────

    def run(self):
        _before = self.result.total()
        log.info("敏感信息泄露检测...")
        self._sample_soft404()
        self._scan_page()
        self._check_exposed_files()
        self._log_module_done("敏感信息泄露", _before)

    def _scan_page(self):
        """扫描首页源码中的敏感信息"""
        r = self.get(self.target)
        if not r:
            return
        for name, (pattern, severity) in PATTERNS.items():
            matches = re.findall(pattern, r.text)
            if not matches:
                continue
            sample = str(matches[0])[:60]
            log.warning(f"[VULN][敏感信息] {name} ({len(matches)} 处)")
            self.result.add("敏感信息泄露", severity,
                            f"源码中发现 {name} ({len(matches)} 处)",
                            sample, url=self.target)

    def _check_exposed_files(self):
        """
        检测敏感文件是否暴露
        三重过滤 + 内容验证，最大化减少误报
        """
        for path, severity, desc, content_sigs in EXPOSED_FILES:
            url = self.build_url(path)
            r   = self.get(url)

            if not r or r.status_code != 200:
                continue

            text = r.text

            # ══ 过滤1：Content-Type 判断 ══════════════════════
            # 真实配置/数据文件不应该是 text/html
            ct = r.headers.get("Content-Type", "").lower()
            if "text/html" in ct:
                # phpinfo.php 例外：它本身就是 HTML 输出
                if "phpinfo" not in path:
                    log.info(f"[软404-CT] {path} Content-Type=html，跳过")
                    continue

            # ══ 过滤2：HTML 内容检测 ══════════════════════════
            # [核心修复] 响应含 HTML 结构特征 = 软404页面，直接跳过
            # phpinfo.php 是唯一合法的 HTML 输出文件
            if "phpinfo" not in path:
                if self._is_html_page(text):
                    log.info(f"[软404-HTML] {path} 响应是HTML页面，跳过")
                    continue

            # ══ 过滤3：软404长度相似度 ════════════════════════
            # [修复] 改为比例判断（>85%相似 = 软404）
            if self._soft404_len > 0:
                ratio = min(len(text), self._soft404_len) / \
                        max(len(text), self._soft404_len)
                if ratio > 0.85:
                    log.info(f"[软404-长度] {path} 相似度{ratio:.0%}，跳过")
                    continue

            # ══ 过滤4：软404关键词 ════════════════════════════
            text_lower = text.lower()
            if any(s in text_lower for s in SOFT_404_WORDS):
                # 同时长度合理（防止正常文件恰好含404字样）
                if len(text) < 10000:
                    log.info(f"[软404-词] {path} 含软404关键词，跳过")
                    continue

            # ══ 内容特征验证 ══════════════════════════════════
            # 必须至少匹配一个专属特征才上报
            if not self._verify_content(text, content_sigs):
                log.info(f"[内容不符] {path} 未匹配专属特征，跳过")
                continue

            # ══ 确认暴露 ══════════════════════════════════════
            log.warning(f"[VULN][文件暴露] {path} → {desc}")
            self.result.add("文件暴露", severity, desc,
                            text[:200], url=url)

    # ── 辅助方法 ──────────────────────────────────────────────

    def _is_html_page(self, text: str) -> bool:
        """
        [核心修复] 判断响应是否为 HTML 页面
        命中任意一个 HTML 特征即认定为软404
        """
        check = text[:2000]  # 只检测头部，效率更高
        for sig in HTML_SIGNATURES:
            if re.search(sig, check, re.I):
                return True
        return False

    def _verify_content(self, text: str, sigs: List[str]) -> bool:
        """
        内容验证：text 必须匹配 sigs 中至少一个
        支持正则和普通字符串，失败时静默跳过
        """
        for sig in sigs:
            try:
                if re.search(sig, text, re.I | re.M):
                    return True
            except re.error:
                if sig in text:
                    return True
        return False
