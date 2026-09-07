"""
Web 缓存欺骗 / OAuth 配置检测模块（主动 / 被动）
Author: 火柴 | GitHub: huocai250
"""
import re
from urllib.parse import urlparse, parse_qs
from core.scanner import BaseScanner
from core.colors import log


class CacheDeceptionScanner(BaseScanner):
    name = "cachedeception"
    passive = False

    def run(self):
        log("INFO", "Web 缓存欺骗检测（伪静态后缀）...")
        base = self.baseline(self.target)
        if not base:
            return
        # 在路径后追加伪静态后缀，若仍返回动态内容且响应被标记可缓存 => 风险
        for suffix in ("/wvscache.css", "/wvscache.js", "%2fwvscache.css",
                       ";wvscache.css", "/..%2fwvscache.css"):
            url = self.target.rstrip("/") + suffix
            r = self.get(url)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            # 返回了和首页类似的动态内容（含表单/脚本），且响应可缓存
            looks_dynamic = ("<form" in body or "<script" in body
                             or "session" in body.lower())
            cacheable = self._cacheable(r)
            if looks_dynamic and cacheable:
                self.add("配置错误", "MEDIUM",
                         "疑似 Web 缓存欺骗：追加伪静态后缀后仍返回动态页面且响应可缓存，"
                         "攻击者可能诱导缓存他人的敏感页面",
                         evidence=f"{suffix} 仍返回动态内容 @ {url}", url=url,
                         confidence="疑似")
                log("VULN", f"[缓存欺骗] {suffix}")
                return

    @staticmethod
    def _cacheable(r):
        cc = r.headers.get("Cache-Control", "").lower()
        xc = r.headers.get("X-Cache", "").lower()
        if any(x in cc for x in ("no-store", "private", "no-cache")):
            return "hit" in xc  # 即便声明不缓存，若命中缓存仍算
        return ("public" in cc or "max-age" in cc or "hit" in xc
                or "age" in {k.lower() for k in r.headers.keys()})


class OAuthScanner(BaseScanner):
    name = "oauth"
    passive = True

    AUTH_PATHS = ["/oauth/authorize", "/authorize", "/oauth2/authorize",
                  "/connect/authorize", "/auth/realms"]

    def run(self):
        log("INFO", "OAuth/OIDC 配置检测...")
        # 1) 页面/重定向中发现 OAuth 授权链接
        found = False
        for p in self.AUTH_PATHS:
            r = self.get(self.url(p))
            if r and r.status_code in (200, 302, 400) and \
               any(k in (r.text or "") + str(r.headers) for k in
                   ("client_id", "redirect_uri", "response_type", "invalid_client",
                    "unsupported_response_type")):
                found = True
                self._check_endpoint(self.url(p), r)
        if not found:
            log("INFO", "  未发现 OAuth 端点")

    def _check_endpoint(self, ep, r):
        # 检测 redirect_uri 是否宽松（接受任意回调）—— 仅用无害探测域观察
        test = ep + "?response_type=code&client_id=test&redirect_uri=https://wvs.evil.example/cb"
        rr = self.get(test, allow_redirects=False)
        if rr and rr.status_code in (301, 302, 303, 307):
            loc = rr.headers.get("Location", "")
            if "wvs.evil.example" in loc:
                self.add("开放重定向", "HIGH",
                         "OAuth 端点接受任意 redirect_uri（重定向到未注册回调），可致令牌窃取",
                         evidence=f"redirect_uri 反射到 {loc[:80]}", url=ep)
                log("VULN", "[OAuth] redirect_uri 校验缺失")
        # state 缺失提示（无法完全判定，给信息级）
        self.add("信息泄露", "INFO",
                 f"发现 OAuth/OIDC 授权端点 {urlparse(ep).path}；请确认强制校验 "
                 "redirect_uri 白名单、启用 state/PKCE 防 CSRF", url=ep, confidence="信息")
