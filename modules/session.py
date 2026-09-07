"""
会话固定 / 敏感页缓存检测模块（主动 / 被动）
Author: 火柴 | GitHub: huocai250
"""
import re
from core.scanner import BaseScanner
from core.colors import log

SESSION_COOKIE_HINTS = ["sess", "sid", "session", "token", "auth", "jsession",
                        "phpsessid", "asp.net_sessionid", "connect.sid"]


class SessionScanner(BaseScanner):
    name = "session"
    passive = False

    def run(self):
        log("INFO", "会话固定检测（是否接受攻击者预置会话 ID）...")
        base = self.baseline(self.target)
        if not base:
            return
        # 会话 Cookie 名：优先从响应头取；取不到则从共享 Cookie 罐里找
        # （扫描中途 Session 已持有该 Cookie，响应可能不再重复 Set-Cookie）
        name = self._session_cookie_name(base)
        if not name:
            log("INFO", "  未观察到会话 Cookie")
            return
        # 预置一个我们自造的会话 ID，看服务端是否「接受并保留」而不重新签发
        forged = "wvsFIXED1234567890"
        r = self.get(self.target, headers={"Cookie": f"{name}={forged}"})
        if not r:
            return
        new_set = r.headers.get("Set-Cookie", "")
        # 若响应没有为该 Cookie 重新签发新值 => 疑似接受固定会话
        reissued = re.search(rf'{re.escape(name)}=([^;,\s]+)', new_set)
        if not reissued or reissued.group(1) == forged:
            self.add("配置错误", "MEDIUM",
                     f"服务端疑似接受外部预置的会话 Cookie '{name}' 且未在访问时重新签发，"
                     "存在会话固定风险（登录后应重置会话 ID）",
                     evidence=f"预置 {name}={forged} 后未见重签发", url=self.target,
                     confidence="疑似")
            log("VULN", f"[会话固定] {name} 未重签发")

    def _session_cookie_name(self, base):
        set_cookie = base.headers.get("Set-Cookie", "")
        for part in set_cookie.split(","):
            cname = part.split("=", 1)[0].strip()
            if any(h in cname.lower() for h in SESSION_COOKIE_HINTS):
                return cname
        # 回退：共享 Session 的 Cookie 罐
        try:
            for c in self.session.cookies:
                if any(h in c.name.lower() for h in SESSION_COOKIE_HINTS):
                    return c.name
        except Exception:
            pass
        return None


class SensitiveCacheScanner(BaseScanner):
    name = "sensitivecache"
    passive = True

    def run(self):
        log("INFO", "敏感页缓存策略检测...")
        urls = {self.target}
        for ip in self.ctx.injection_points:
            u = ip["url"].lower()
            if any(k in u for k in ("login", "account", "profile", "admin",
                                    "user", "dashboard", "setting", "order",
                                    "checkout", "pay", "token")):
                urls.add(ip["url"])
        self.map(self._check, list(urls)[:30])

    def _check(self, url):
        r = self.probe_get(url)
        if not r or r.status_code != 200:
            return None
        body = r.text or ""
        # 页面看起来含敏感/个性化内容
        sensitive = bool(re.search(r'(logout|sign\s*out|my account|个人中心|'
                                   r'password|csrf|session|authenticity_token|'
                                   r'注销|退出登录|账户)', body, re.I))
        if not sensitive:
            return None
        cc = r.headers.get("Cache-Control", "").lower()
        pragma = r.headers.get("Pragma", "").lower()
        cacheable = not any(x in cc for x in ("no-store", "no-cache", "private")) \
            and "no-cache" not in pragma
        if cacheable and ("public" in cc or "max-age" in cc or not cc):
            log("VULN", f"[敏感页缓存] {url}")
            self.add("配置错误", "MEDIUM",
                     "疑似敏感/个性化页面未禁止缓存（缺少 no-store/private），"
                     "可能被共享缓存或 CDN 缓存并泄露给其他用户",
                     evidence=f"Cache-Control: {cc or '(空)'} @ {url}", url=url,
                     confidence="疑似")
            return url
        return None
