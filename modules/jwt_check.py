"""
JWT 安全分析模块（被动 / 仅分析）
Author: 火柴 | GitHub: huocai250

从 Cookie / Authorization 头 / 页面正文中发现 JWT，并做**静态安全分析**：
  - alg=none（可被伪造）
  - 缺少 exp（永不过期）
  - 敏感声明（password / role / is_admin 等出现在可解码 payload 中）
  - 弱签名算法提示（HS256 对称密钥若泄露即可伪造 —— 仅提示，不做爆破）

说明：本模块只做 base64 解码与结构分析，**不尝试破解密钥、不伪造 token**。
"""
import re
import json
import base64
from core.scanner import BaseScanner
from core.colors import log

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*')
SENSITIVE_CLAIMS = ["password", "passwd", "pwd", "secret", "is_admin",
                    "isadmin", "role", "roles", "admin", "priv", "authorities"]


def _b64d(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


class JWTScanner(BaseScanner):
    name = "jwt"
    passive = True

    def run(self):
        log("INFO", "JWT 安全分析（静态）...")
        tokens = self._collect_tokens()
        if not tokens:
            log("INFO", "  未发现 JWT")
            return
        seen = set()
        for tok in tokens:
            if tok in seen:
                continue
            seen.add(tok)
            self._analyze(tok)

    def _collect_tokens(self):
        toks = []
        # 请求头/Cookie 里我们主动带的
        for v in list(self.config.cookies.values()) + list(self.config.headers.values()):
            toks += JWT_RE.findall(str(v))
        # 目标响应（Set-Cookie / 正文）
        r = self.baseline(self.target)
        if r:
            blob = " ".join(f"{k}: {v}" for k, v in r.headers.items())
            toks += JWT_RE.findall(blob)
            toks += JWT_RE.findall(r.text or "")
        return toks

    def _analyze(self, token: str):
        parts = token.split(".")
        if len(parts) < 2:
            return
        try:
            header = json.loads(_b64d(parts[0]) or b"{}")
            payload = json.loads(_b64d(parts[1]) or b"{}")
        except Exception:
            return

        short = token[:16] + "…"
        alg = str(header.get("alg", "")).lower()
        log("VULN", f"发现 JWT: {short} (alg={header.get('alg')})")

        if alg == "none":
            self.add("JWT 安全", "HIGH",
                     "JWT 使用 alg=none，签名可被绕过/伪造",
                     evidence=f"header={header}", url=self.target)
        elif alg.startswith("hs"):
            self.add("JWT 安全", "LOW",
                     f"JWT 使用对称算法 {header.get('alg')}；若签名密钥泄露即可伪造 token",
                     evidence=f"alg={header.get('alg')}", url=self.target,
                     confidence="信息")

        if "exp" not in payload:
            self.add("JWT 安全", "MEDIUM",
                     "JWT 缺少 exp（过期时间），token 永久有效",
                     evidence=f"claims={list(payload.keys())}", url=self.target)

        hit = [c for c in SENSITIVE_CLAIMS if c in
               [str(k).lower() for k in payload.keys()]]
        if hit:
            self.add("JWT 安全", "LOW",
                     f"JWT payload 含敏感/权限声明: {', '.join(hit)}（payload 非加密，任何人可解码）",
                     evidence=f"claims={list(payload.keys())}", url=self.target,
                     confidence="信息")
