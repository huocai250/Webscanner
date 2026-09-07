"""
HTTP 参数污染 (HPP) 检测模块（主动）
Author: 火柴 | GitHub: huocai250

发送重复参数，观察后端解析行为（取首/取尾/拼接/全取）。当不同组件解析不一致
时，可被用于绕过 WAF、越权或改变业务逻辑。此处只做**解析行为检测与提示**。
"""
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url


class HTTPParamPollutionScanner(BaseScanner):
    name = "hpp"
    passive = False

    def run(self):
        log("INFO", "HTTP 参数污染 (HPP) 检测...")
        targets = []
        seen = set()
        for ip in self.ctx.injection_points:
            if ip["method"] != "GET":
                continue
            for pname in ip["params"]:
                key = (ip["url"], pname)
                if key not in seen:
                    seen.add(key)
                    targets.append((ip["url"], dict(ip["params"]), pname))
        if not targets:
            log("INFO", "  无 GET 参数可测")
            return
        self.map(self._test, targets)

    def _test(self, target):
        url, params, pname = target
        va, vb = "wvsHPPaaa", "wvsHPPbbb"
        # 单值基线
        single = dict(params); single[pname] = va
        r1 = self.get(build_url(url, single))
        if not r1:
            return None
        # 重复参数：手动拼接 query（build_url 会去重，故直接构造）
        base = build_url(url, {k: v for k, v in params.items() if k != pname})
        sep = "&" if "?" in base else "?"
        dup_url = f"{base}{sep}{pname}={va}&{pname}={vb}"
        r2 = self.get(dup_url)
        if not r2 or not r2.text:
            return None
        body = r2.text
        has_a, has_b = va in body, vb in body
        behavior = None
        if has_a and has_b:
            behavior = "两值均被处理（可能拼接）"
        elif has_b and not has_a:
            behavior = "取最后一个值"
        elif has_a and not has_b:
            behavior = "取第一个值"
        # 仅当重复参数导致与单值不同的可见行为时提示
        if behavior and (has_a and has_b):
            log("VULN", f"[HPP] 参数 {pname}：{behavior}")
            self.add("配置错误", "LOW",
                     f"参数 '{pname}' 存在 HTTP 参数污染迹象（{behavior}），"
                     "若前后端解析不一致可被用于绕过校验/WAF",
                     evidence=f"dup {pname} @ {url}", url=url, confidence="信息")
            return f"{pname}@{url}"
        return None
