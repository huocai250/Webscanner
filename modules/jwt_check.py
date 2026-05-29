"""
JWT 安全检测模块
Author: 火柴 | GitHub: huocai250

修复:
- _test_token 不再仅凭 status_code==200 判断绕过成功（误报率太高）
  改为：对比携带合法token vs 伪造token的响应差异
- 增加更多弱密钥
"""
import re
import json
import base64
import hmac
import hashlib
from core.scanner import BaseScanner
from core.colors import log

WEAK_SECRETS = [
    "secret", "password", "123456", "test", "key", "jwt",
    "admin", "qwerty", "abc123", "changeme", "default",
    "supersecret", "mysecret", "jwttoken", "token",
    "", "null", "undefined", "jwt_secret", "jwt-secret",
    "your-256-bit-secret", "your-secret-key", "secretkey",
    "s3cr3t", "p@ssw0rd", "1234567890", "HS256",
]


def _b64d(s: str) -> str:
    s += "=" * (4 - len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class JWTScanner(BaseScanner):
    def run(self):
        log("INFO", "JWT 安全检测...")
        tokens = self._find_tokens()
        if not tokens:
            log("SKIP", "未在响应中发现 JWT Token")
            return
        for token in tokens[:3]:   # 最多分析3个token
            log("INFO", f"发现 JWT: {token[:50]}...")
            self._analyze(token)

    def _find_tokens(self):
        r = self.get(self.target)
        if not r:
            return []
        pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'
        tokens = re.findall(pattern, r.text)
        for v in r.headers.values():
            tokens += re.findall(pattern, v)
        return list(dict.fromkeys(tokens))  # 去重保序

    def _analyze(self, token: str):
        parts = token.split(".")
        if len(parts) != 3:
            return

        header_raw, payload_raw, sig = parts
        header  = self._safe_json(_b64d(header_raw))
        payload = self._safe_json(_b64d(payload_raw))
        if not header:
            return

        alg = header.get("alg", "").upper()
        log("INFO", f"  JWT alg={alg}")

        # 1. none 算法
        if alg == "NONE":
            log("VULN", "[JWT] 使用 none 算法，签名未验证！")
            self.result.add("JWT", "CRITICAL",
                            "JWT 使用 none 算法，可伪造任意 Token",
                            f"Header: {header}", url=self.target)

        # 2. 尝试 none 算法绕过：比较有/无签名的响应差异
        if alg in ["HS256", "HS384", "HS512", "RS256", "NONE"]:
            fake_hdr = _b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            fake_tok = f"{fake_hdr}.{payload_raw}."
            self._test_none_bypass(token, fake_tok)

        # 3. 弱密钥爆破（仅 HMAC 算法）
        if alg in ["HS256", "HS384", "HS512"]:
            self._brute_secret(header_raw, payload_raw, sig, alg)

        # 4. Payload 敏感字段
        if payload:
            self._check_payload_leaks(payload)

        # 5. 无过期时间
        if payload and "exp" not in payload:
            log("WARN", "[JWT] Token 无过期时间")
            self.result.add("JWT", "MEDIUM",
                            "JWT Token 未设置过期时间，存在永久有效风险",
                            url=self.target)

        # 6. alg:RS256 降级为 HS256 攻击提示
        if alg == "RS256":
            log("WARN", "[JWT] RS256 算法可能存在 alg 混淆攻击（RS256→HS256）")
            self.result.add("JWT", "LOW",
                            "JWT 使用 RS256，需测试 alg confusion（RSA→HMAC）",
                            url=self.target)

    def _test_none_bypass(self, orig_token: str, fake_token: str):
        """
        修复：比较正常请求与伪造 token 请求的响应
        只有当伪造 token 响应与原始 token 相似（而非报错）才判定为绕过
        """
        orig_r = self.get(self.target,
                          headers={"Authorization": f"Bearer {orig_token}"})
        fake_r = self.get(self.target,
                          headers={"Authorization": f"Bearer {fake_token}"})
        no_auth_r = self.get(self.target)

        if not (orig_r and fake_r and no_auth_r):
            return

        orig_len    = len(orig_r.text)
        fake_len    = len(fake_r.text)
        no_auth_len = len(no_auth_r.text)

        # 伪造 token 响应与合法 token 相近，但与无 token 响应差异明显
        if (abs(fake_len - orig_len) < 50 and
                abs(fake_len - no_auth_len) > 100 and
                fake_r.status_code == orig_r.status_code):
            log("VULN", "[JWT] none 算法绕过成功！伪造 Token 被服务端接受")
            self.result.add("JWT", "CRITICAL",
                            "JWT none 算法绕过：服务端接受无签名 Token",
                            url=self.target)

    def _brute_secret(self, hdr_raw: str, pay_raw: str, sig: str, alg: str):
        fn_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn = fn_map.get(alg, hashlib.sha256)
        msg = f"{hdr_raw}.{pay_raw}".encode()
        for secret in WEAK_SECRETS:
            expected = _b64e(hmac.new(secret.encode(), msg, hash_fn).digest())
            if expected == sig:
                log("VULN", f"[JWT] 弱密钥: '{secret}'")
                self.result.add("JWT", "CRITICAL",
                                f"JWT 签名密钥为弱密钥: '{secret}'",
                                url=self.target)
                return

    def _check_payload_leaks(self, payload: dict):
        sensitive = ["password", "passwd", "secret", "token",
                     "key", "credit_card", "ssn", "id_card", "private"]
        for k in payload:
            if any(s in k.lower() for s in sensitive):
                log("WARN", f"[JWT] Payload 含敏感字段: {k}")
                self.result.add("JWT", "MEDIUM",
                                f"JWT Payload 含敏感字段: {k}",
                                url=self.target)

    def _safe_json(self, s: str):
        try:
            return json.loads(s)
        except Exception:
            return None
