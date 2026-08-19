"""
版本已知漏洞提示模块（被动 / 信息级）
Author: 火柴 | GitHub: huocai250

基于指纹识别得到的组件与版本，比对一个精简的「已知高危版本」库，给出
「该版本存在已知 CVE」的**提示**（不做利用，也不保证一定可利用，需人工核实）。
"""
import re
from core.scanner import BaseScanner
from core.colors import log

# (组件名小写, 版本判定函数 or 上限版本, 说明) —— 用「小于某版本即提示」的简单规则
# 规则来源为公开披露的高危 CVE 影响版本，仅作提示。
def _lt(v, ceiling):
    return _cmp(v, ceiling) < 0

def _cmp(a, b):
    pa = [int(x) for x in re.findall(r'\d+', a)][:4]
    pb = [int(x) for x in re.findall(r'\d+', b)][:4]
    pa += [0] * (4 - len(pa)); pb += [0] * (4 - len(pb))
    return (pa > pb) - (pa < pb)

# name -> list of (ceiling_version, cve_desc, severity)
KNOWN = {
    "nginx": [("1.21.0", "多个 CVE（含 CVE-2021-23017 DNS resolver 堆溢出）", "HIGH")],
    "apache": [("2.4.51", "CVE-2021-42013 路径穿越/RCE（若 mod_cgi 开启）", "HIGH")],
    "openssl": [("1.1.1", "已过时分支，存在多个已知 CVE", "MEDIUM")],
    "php": [("7.4.0", "7.3 及以下已停止安全维护", "MEDIUM")],
    "wordpress": [("5.8.3", "旧版本存在多个已披露漏洞", "MEDIUM")],
    "jquery": [("3.5.0", "CVE-2020-11022/11023 jQuery XSS", "MEDIUM")],
    "bootstrap": [("3.4.1", "旧版 Bootstrap 存在 XSS (CVE-2018-14041 等)", "LOW")],
    "tomcat": [("9.0.31", "多个已披露漏洞（含 Ghostcat CVE-2020-1938）", "HIGH")],
    "spring boot": [("2.5.12", "旧版本存在多个已披露漏洞", "MEDIUM")],
    "drupal": [("9.2.0", "旧版本存在多个已披露漏洞", "MEDIUM")],
}


class CVEVersionScanner(BaseScanner):
    name = "cveversion"
    passive = True

    def run(self):
        fps = [f for f in self.ctx.fingerprints if f.get("version")]
        if not fps:
            return
        log("INFO", "已知版本漏洞提示（基于指纹版本比对）...")
        for f in fps:
            name = f["name"].lower()
            ver = f["version"]
            rules = KNOWN.get(name)
            if not rules:
                continue
            for ceiling, desc, sev in rules:
                try:
                    if _lt(ver, ceiling):
                        log("VULN", f"[版本漏洞] {f['name']} {ver} < {ceiling}")
                        self.add("信息泄露", sev,
                                 f"{f['name']} {ver} 版本较旧：{desc}"
                                 f"（建议升级到 ≥ {ceiling} 并人工核实）",
                                 evidence=f"{f['name']}/{ver}", url=self.target,
                                 confidence="信息")
                except Exception:
                    pass
