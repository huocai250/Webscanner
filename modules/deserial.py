"""
不安全反序列化指示检测模块（被动）
Author: 火柴 | GitHub: huocai250

在 Cookie / 参数 / 响应中识别常见序列化对象特征（Java/PHP/Python/.NET/Ruby），
这类数据若被服务端不安全反序列化，历史上常导致 RCE。本模块只**识别特征并
提示加固**，不构造任何 gadget、不发起利用。
"""
import re
import base64
from core.scanner import BaseScanner
from core.colors import log

# (语言/框架, 判定函数)
def _java_b64(v):
    # Java 序列化 magic: 0xAC 0xED -> base64 前缀 "rO0"
    return v.startswith("rO0AB") or v.startswith("rO0")

def _php_serialized(v):
    # PHP 序列化以类型字符开头：O:(对象) a:(数组) s:(字符串) 等
    # 只认结构化的对象/数组前缀，避免把普通字符串/JSON 误判
    return bool(re.match(r'^(O:\d+:"|a:\d+:\{|O:\+?\d+:)', v))

def _python_pickle(v):
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4))
        return raw[:2] in (b"\x80\x04", b"\x80\x03", b"\x80\x02") or raw[:1] == b"("
    except Exception:
        return False

def _dotnet_viewstate(v):
    return v.startswith("/wEP") or v.startswith("/wE")

def _ruby_marshal(v):
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4))
        return raw[:2] == b"\x04\x08"
    except Exception:
        return False

CHECKS = [
    ("Java 序列化对象", _java_b64, "HIGH"),
    ("PHP 序列化对象", _php_serialized, "HIGH"),
    ("Python pickle", _python_pickle, "HIGH"),
    (".NET ViewState", _dotnet_viewstate, "MEDIUM"),
    ("Ruby Marshal", _ruby_marshal, "HIGH"),
]


class DeserializationScanner(BaseScanner):
    name = "deserial"
    passive = True

    def run(self):
        log("INFO", "不安全反序列化指示检测（特征识别）...")
        values = self._collect()
        seen = set()
        for src, val in values:
            v = str(val).strip()
            if len(v) < 8 or v in seen:
                continue
            seen.add(v)
            for label, fn, sev in CHECKS:
                try:
                    if fn(v):
                        log("VULN", f"[反序列化] {label} 出现在 {src}")
                        self.add("信息泄露", sev,
                                 f"{src} 含 {label} 特征；若服务端不安全反序列化，"
                                 "历史上可导致 RCE，请确认使用安全反序列化并做完整性校验",
                                 evidence=f"{src}: {v[:40]}…", url=self.target,
                                 confidence="疑似")
                        break
                except Exception:
                    pass

    def _collect(self):
        out = []
        # 我们发送的 Cookie / 头
        for k, v in self.config.cookies.items():
            out.append((f"Cookie[{k}]", v))
        # 目标响应的 Set-Cookie 值 + 爬虫发现的参数值
        r = self.baseline(self.target)
        if r:
            for k, v in r.headers.items():
                if k.lower() == "set-cookie":
                    for part in v.split(";"):
                        if "=" in part:
                            ck, cv = part.split("=", 1)
                            out.append((f"Set-Cookie[{ck.strip()}]", cv.strip()))
        for ip in self.ctx.injection_points:
            for pk, pv in ip["params"].items():
                if pv:
                    out.append((f"参数[{pk}]", pv))
        return out
