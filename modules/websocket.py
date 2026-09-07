"""
WebSocket / 实时端点检测模块（被动）
Author: 火柴 | GitHub: huocai250

从页面与 JS 中发现 WebSocket（ws://、wss://）、Socket.IO、SignalR 等实时端点，
并提示常见风险（明文 ws、需人工核实 Origin 校验）。仅发现，不建立长连接、不注入。
"""
import re
from urllib.parse import urlparse, urljoin
from core.scanner import BaseScanner
from core.colors import log

WS_RE = re.compile(r'wss?://[a-zA-Z0-9.\-:/_?=&%]+')
RT_PATHS = [("/socket.io/?EIO=4&transport=polling", "Socket.IO",
             ["sid", "upgrades", "pingInterval"]),
            ("/signalr/negotiate", "SignalR", ["ConnectionId", "connectionToken"]),
            ("/ws", "WebSocket 端点", ["Upgrade", "websocket"]),
            ("/websocket", "WebSocket 端点", ["Upgrade", "websocket"])]


class WebSocketScanner(BaseScanner):
    name = "websocket"
    passive = True

    def run(self):
        log("INFO", "WebSocket / 实时端点检测...")
        found = set()
        # 1) 页面/JS 中的 ws 端点
        r = self.baseline(self.target)
        if r and r.text:
            for m in WS_RE.finditer(r.text):
                found.add(m.group(0))
            # 抓取内联/外链 JS 里的
            for jm in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I):
                ju = urljoin(r.url, jm.group(1))
                if urlparse(ju).netloc == urlparse(self.target).netloc:
                    jr = self.get(ju)
                    if jr and jr.text:
                        for m in WS_RE.finditer(jr.text):
                            found.add(m.group(0))
        is_https = self.target.startswith("https")
        for ws in list(found)[:15]:
            if ws.startswith("ws://") and is_https:
                self.add("配置错误", "MEDIUM",
                         f"HTTPS 页面使用明文 WebSocket（{ws[:60]}），存在中间人风险，应改用 wss://",
                         evidence=ws, url=self.target, confidence="疑似")
                log("VULN", f"[WebSocket] 明文 ws:// @ {ws[:40]}")
            else:
                self.add("信息泄露", "INFO",
                         f"发现 WebSocket 端点 {ws[:60]}（请人工核实是否校验 Origin 与鉴权）",
                         evidence=ws, url=self.target, confidence="信息")
        # 2) 常见实时框架端点探测
        self.map(self._probe_rt, RT_PATHS)

    def _probe_rt(self, entry):
        path, label, signs = entry
        r = self.get(self.url(path))
        if r and r.status_code in (200, 101, 400) and \
           any(s in (r.text or "") for s in signs):
            self.add("信息泄露", "INFO",
                     f"发现 {label} 端点: {path}（请核实鉴权与 Origin 校验）",
                     evidence=f"{path} -> {r.status_code}", url=r.url, confidence="信息")
            return path
        return None
