"""
模板引擎（nuclei 风格 YAML 签名）
Author: 火柴 | GitHub: huocai250

从 templates/ 目录加载 YAML/JSON 模板，每个模板描述一次或多次 HTTP 请求
及匹配规则（status / word / regex / header），命中即产生一条发现。
用户可自行添加模板，无需改代码即可扩展检测规则（--templates DIR）。

安全边界：模板只做「请求 + 匹配」式的**检测**，不含利用逻辑；本引擎不执行
模板中的任何代码，仅按声明式规则匹配响应。
"""
import os
import re
import glob

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

import json

SEV_MAP = {
    "info": "INFO", "low": "LOW", "medium": "MEDIUM",
    "high": "HIGH", "critical": "CRITICAL",
}


def load_templates(dirs) -> list:
    """加载目录（可多个）下所有 .yaml/.yml/.json 模板，返回模板 dict 列表。"""
    if isinstance(dirs, str):
        dirs = [dirs]
    templates = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        files = []
        for ext in ("*.yaml", "*.yml", "*.json"):
            files += glob.glob(os.path.join(d, "**", ext), recursive=True)
        for path in sorted(set(files)):
            for tpl in _load_file(path):
                if _valid(tpl):
                    tpl.setdefault("_file", os.path.basename(path))
                    templates.append(tpl)
    return templates


def _load_file(path) -> list:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    try:
        if path.endswith(".json"):
            data = json.loads(text)
        elif _HAS_YAML:
            data = list(yaml.safe_load_all(text))
            data = data[0] if len(data) == 1 else data
        else:
            return []
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def _valid(tpl) -> bool:
    return isinstance(tpl, dict) and "requests" in tpl and "id" in tpl


def count_checks(templates) -> int:
    """统计模板贡献的检测点数量（每个 request 的每个 path 记一次）。"""
    n = 0
    for tpl in templates:
        for req in tpl.get("requests", []):
            paths = req.get("paths") or ([req.get("path")] if req.get("path") else [""])
            n += max(1, len(paths))
    return n


class TemplateRunner:
    """对单个目标执行一批模板。由 modules/nuclei.py 调用。"""

    def __init__(self, scanner, templates):
        self.s = scanner              # BaseScanner 实例（提供 get/post/add/url）
        self.templates = templates

    def run_template(self, tpl):
        info = tpl.get("info", {}) or {}
        sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), "INFO")
        name = info.get("name", tpl.get("id"))
        category = info.get("category", "配置错误")
        hits = []

        for req in tpl.get("requests", []):
            method = str(req.get("method", "GET")).upper()
            paths = req.get("paths") or [req.get("path", "")]
            headers = req.get("headers") or None
            body = req.get("body")
            cond = str(req.get("matchers-condition", "or")).lower()
            matchers = req.get("matchers", []) or []

            for p in paths:
                url = self.s.url(p) if p else self.s.target
                if method == "POST":
                    r = self.s.post(url, data=body, headers=headers)
                elif headers:
                    r = self.s.get(url, headers=headers)
                else:
                    r = self.s.probe_get(url)   # 幂等 GET 走共享缓存，去重
                if r is None:
                    continue
                if self._eval(matchers, cond, r):
                    self.s.add(category, sev,
                               f"[模板:{tpl.get('id')}] {name}",
                               evidence=f"{method} {url} -> {r.status_code}",
                               url=url,
                               confidence="疑似" if sev in ("INFO", "LOW") else "确认")
                    hits.append(tpl.get("id"))
                    break   # 该模板命中一次即可
        return hits

    def _eval(self, matchers, cond, resp) -> bool:
        if not matchers:
            return False
        results = [self._match(m, resp) for m in matchers]
        return all(results) if cond == "and" else any(results)

    def _match(self, m, resp) -> bool:
        mtype = m.get("type")
        part = m.get("part", "body")
        neg = bool(m.get("negative", False))
        body = resp.text or ""
        header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        hay = {"body": body, "header": header_blob,
               "all": body + "\n" + header_blob}.get(part, body)
        ci = bool(m.get("case-insensitive", False))

        ok = False
        if mtype == "status":
            ok = resp.status_code in (m.get("status") or [])
        elif mtype == "word":
            words = m.get("words") or []
            c = str(m.get("condition", "or")).lower()
            h = hay.lower() if ci else hay
            checks = [(w.lower() if ci else w) in h for w in words]
            ok = all(checks) if c == "and" else any(checks)
        elif mtype == "regex":
            pats = m.get("regex") or []
            c = str(m.get("condition", "or")).lower()
            flags = re.I if ci else 0
            checks = []
            for p in pats:
                try:
                    checks.append(bool(re.search(p, hay, flags)))
                except re.error:
                    checks.append(False)
            ok = all(checks) if c == "and" else any(checks)
        elif mtype == "header":
            names = [n.lower() for n in (m.get("headers") or [])]
            present = {k.lower() for k in resp.headers.keys()}
            ok = any(n in present for n in names)
        return (not ok) if neg else ok
