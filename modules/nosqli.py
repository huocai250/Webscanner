"""
NoSQL 注入检测模块（主动）
Author: 火柴 | GitHub: huocai250

针对 MongoDB 等 NoSQL 后端，注入运算符/布尔差异 payload，通过错误特征或
真假 payload 的响应差异判断是否存在 NoSQL 注入。仅检测，不做数据提取。
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

# 错误特征（应用把 NoSQL 报错回显）
ERROR_SIGNS = [
    r"MongoError", r"MongoServerError", r"BSONError", r"CastError",
    r"unexpected token", r"\$where", r"E11000", r"MongoParseError",
    r"couldn't parse", r"Cannot read propert(y|ies)", r"failed to parse",
]

# (真 payload, 假 payload) —— 布尔差异检测
BOOL_PAIRS = [
    ("[$ne]=wvs_nomatch", "[$eq]=wvs_nomatch"),
    ("' || '1'=='1", "' || '1'=='2"),
    ("'||1==1//", "'||1==2//"),
]

NOSQL_PARAMS = ["id", "user", "username", "name", "email", "search", "q",
                "filter", "query", "uid", "userid", "login"]


class NoSQLiScanner(BaseScanner):
    name = "nosqli"
    passive = False

    def run(self):
        log("INFO", "NoSQL 注入检测（错误特征 + 布尔差异，并发）...")
        targets = self.injection_targets(NOSQL_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        # 1) 错误特征
        for payload in ("'\"{}[]", "[$ne]=1", "{\"$gt\":\"\"}"):
            r = self._send(url, method, params, pname, payload)
            if r and r.text:
                for sign in ERROR_SIGNS:
                    if re.search(sign, r.text, re.I):
                        log("VULN", f"[NoSQL注入] 参数 {pname}（错误特征）")
                        self.add("NoSQL 注入", "HIGH",
                                 f"参数 '{pname}' 触发 NoSQL 错误，疑似 NoSQL 注入",
                                 evidence=f"payload={payload} 命中 '{sign}' @ {url}",
                                 url=url, confidence="疑似")
                        return f"{pname}@{url}"
        # 2) 布尔差异
        base = self._send(url, method, params, pname, "wvs_baseline_val")
        if not base:
            return None
        blen = len(base.text or "")
        for ptrue, pfalse in BOOL_PAIRS:
            rt = self._send(url, method, params, pname, ptrue, raw_kv=True)
            rf = self._send(url, method, params, pname, pfalse, raw_kv=True)
            if not rt or not rf:
                continue
            lt, lf = len(rt.text or ""), len(rf.text or "")
            # 真 payload 明显不同于假 payload 且不同于基线 => 疑似
            if abs(lt - lf) > 40 and abs(lt - blen) > 40:
                log("VULN", f"[NoSQL注入] 参数 {pname}（布尔差异）")
                self.add("NoSQL 注入", "MEDIUM",
                         f"参数 '{pname}' 对 NoSQL 运算符呈现布尔差异，疑似注入",
                         evidence=f"true/false 长度差异 @ {url}", url=url,
                         confidence="疑似")
                return f"{pname}@{url}"
        return None

    def _send(self, url, method, params, pname, payload, raw_kv=False):
        test = dict(params)
        if raw_kv and payload.startswith("["):
            # 形如 param[$ne]=x，需要改写 key
            test.pop(pname, None)
            key = pname + payload.split("=")[0]
            val = payload.split("=", 1)[1] if "=" in payload else ""
            test[key] = val
        else:
            test[pname] = payload
        if method == "POST":
            return self.post(url, data=test)
        return self.get(build_url(url, test))
