"""
PoC 自动化扫描验证模块（v12 核心）
Author: 火柴 | GitHub: huocai250

加载内置 PoC 库（pocs/，nuclei 兼容 + 内置中文应急模板）并执行自动化验证。
运行方式：
  python main.py https://target                     # 指纹匹配 + 内置应急集
  python main.py https://target --poc-all           # 全库扫描
  python main.py https://target --poc-tags cve,rce  # 按标签筛选
  python main.py https://target --poc-only          # 只做 PoC 扫描
  python main.py --list-pocs                        # 查看模板库清单

安全边界：只对已授权目标执行；默认载荷为验证型（回显标记 / 版本指纹 /
无害表达式），不包含破坏性利用、持久化或数据窃取载荷。
"""
import os
import re

from core.scanner import BaseScanner
from core.colors import log, raw, Colors
from core.poc_engine import (
    load_poc_dirs, PocRunner, poc_stats,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILTIN_DIR = os.path.join(ROOT, "pocs", "builtin")     # 内置中文应急模板（YAML）
CUSTOM_DIR = os.path.join(ROOT, "pocs", "custom")       # 用户自定义（YAML）
INDEX_FILE = os.path.join(ROOT, "pocs", "index.json")   # 预构建索引（nuclei 库）


def library_dirs():
    dirs = []
    if os.path.isdir(BUILTIN_DIR):
        dirs.append(BUILTIN_DIR)
    if os.path.isdir(CUSTOM_DIR):
        dirs.append(CUSTOM_DIR)
    return dirs


def load_library(extra_dirs=None):
    """加载完整 PoC 库：预构建索引 + 内置/自定义 YAML + 用户 --pocs 目录。"""
    if os.path.isfile(INDEX_FILE):
        tpls = load_poc_dirs(library_dirs(), index_file=INDEX_FILE, use_index=True)
    else:
        # 无预构建索引时回退为全量实时解析（较慢但可用），并可用工具重建索引
        dirs = library_dirs() + [os.path.join(ROOT, "pocs", "nuclei")]
        tpls = load_poc_dirs(dirs, index_file=None, use_index=False)
    for d in extra_dirs or []:
        if not d or not os.path.isdir(d):
            continue
        tpls = load_poc_dirs([d], index_file=None, use_index=False) + tpls
    # 全局去重（自定义目录与内置库可能 id 重复，优先保留自定义模板）
    seen, out = set(), []
    for t in tpls:
        if t.get("id") in seen:
            continue
        seen.add(t.get("id"))
        out.append(t)
    return out


def _tag_list(info):
    tags = info.get("tags") or ""
    if isinstance(tags, list):
        return [str(t).strip().lower() for t in tags]
    return [t.strip().lower() for t in str(tags).split(",") if t.strip()]


def _meta_products(info):
    md = info.get("metadata") or {}
    prod = md.get("product") or md.get("products") or []
    if isinstance(prod, str):
        prod = [prod]
    out = []
    for p in prod:
        out += [x.strip().lower() for x in str(p).split(",") if x.strip()]
    return out


def _fingerprint_match(info, techs):
    """模板标签/产品名是否与已识别指纹匹配（模糊子串匹配，避免误配）。"""
    if not techs:
        return False
    keys = set(_tag_list(info)) | set(_meta_products(info))
    keys |= {str(info.get("name", "")).lower()}
    for k in keys:
        if len(k) < 3:
            continue
        for t in techs:
            if len(t) < 3:
                continue
            if k == t or k in t or t in k:
                return True
    return False


def _uses_oob(tpl):
    """模板是否包含 OOB 探测标记（interactsh-url）。"""
    try:
        return "{{interactsh-url}}" in str(tpl)
    except Exception:
        return False


class PoCScanner(BaseScanner):
    name = "poc"
    passive = False

    def run(self):
        cfg = self.config
        templates = load_library(getattr(cfg, "poc_dirs", None))
        if not templates:
            log("WARN", "PoC 模板库为空（pocs/ 缺失？），跳过 PoC 扫描")
            return

        stats = poc_stats(templates)
        selected = self._select(templates)
        if not selected:
            log("INFO", f"PoC 库 {stats['total']} 个模板，当前条件下无匹配模板")
            return

        log("INFO", f"PoC 扫描：库 {stats['total']} 个，选中 {len(selected)} 个执行"
                    f"（{stats['runnable']} 可运行）")
        runner = PocRunner(self, selected, canary=getattr(cfg, "canary", None))
        results = self.map(
            lambda t: (t, runner.run_template(t)), selected,
            workers=max(1, min(self.threads, len(selected))))
        matched = [h for _, hs in results if hs for h in hs]
        if not matched:
            log("INFO", "  PoC 带内未命中")

        oob_sent = 0
        for tpl, hs in results:
            if not hs and _uses_oob(tpl):
                oob_sent += 1
                self.add("PoC验证", "INFO",
                         f"[PoC:{tpl.get('id')}] 已发送 OOB 探测，"
                         "请到 --canary 指定的 collaborator 确认回连",
                         evidence=f"canary: {getattr(cfg, 'canary', None) or 'oob.canary.example'}",
                         url=self.target, confidence="信息")
        if oob_sent:
            log("INFO", f"  OOB 探测已发送 {oob_sent} 个模板（需 collaborator 确认）")

        by_sev = {}
        for h in matched:
            self.add(h["category"], h["severity"],
                     f"[PoC:{h['id']}] {h['name']}",
                     evidence=h["evidence"], url=h["url"],
                     confidence=h["confidence"])
            by_sev[h["severity"]] = by_sev.get(h["severity"], 0) + 1
        log("VULN", f"PoC 命中 {len(matched)} 项："
                   + " ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))

    def _select(self, templates):
        cfg = self.config
        ids = set()
        for x in (getattr(cfg, "poc_ids", None) or []):
            ids.update(i.strip().lower() for i in str(x).split(",") if i.strip())
        tags = set()
        for x in (getattr(cfg, "poc_tags", None) or []):
            tags.update(t.strip().lower() for t in str(x).split(",") if t.strip())
        sevs = set()
        for x in (getattr(cfg, "poc_severity", None) or []):
            sevs.update(s.strip().lower() for s in str(x).split(",") if s.strip())

        techs = self.ctx.tech_names()
        all_flag = bool(getattr(cfg, "poc_all", False))
        out = []
        for t in templates:
            tpl_id = str(t.get("id", "")).lower()
            info = t.get("info") or {}
            tsev = str(info.get("severity", "info")).lower()
            ttags = set(_tag_list(info))
            if ids and not (tpl_id in ids or ttags & ids):
                continue
            if not ids and tags and not (ttags & tags):
                continue
            if sevs and tsev not in sevs:
                continue
            if ids or tags or sevs or all_flag:
                out.append(t)
                continue
            # 默认：内置应急模板全跑 + 指纹匹配的 nuclei 库模板
            src = str(t.get("_source", ""))
            if src.startswith("nuclei"):
                if _fingerprint_match(info, techs):
                    out.append(t)
            else:
                out.append(t)
        return out


def list_pocs(extra_dirs=None, tag=None, quiet=False):
    """列出模板库清单（--list-pocs 用）。"""
    templates = load_library(extra_dirs)
    stats = poc_stats(templates)
    want = {t.strip().lower() for t in str(tag or "").split(",") if t.strip()}
    rows, filtered = [], []
    for t in sorted(templates, key=lambda x: (str((x.get("info") or {}).get("severity", "info")),
                                               str(x.get("id", "")))):
        info = t.get("info") or {}
        if want and not (set(_tag_list(info)) & want):
            continue
        filtered.append(t)
        rows.append((str(info.get("severity", "info")).upper(),
                     t.get("id", "?"),
                     str(info.get("name", "")),
                     ",".join(_tag_list(info)[:6])))
    raw(f"\n{Colors.PURPLE}{'─'*70}{Colors.RESET}")
    raw(f"{Colors.BOLD}  PoC 模板库: {stats['total']} 个"
        f"（可运行 {stats['runnable']}）{Colors.RESET}")
    sev = stats["severity"]
    raw(f"  severity: " + " ".join(f"{k}={sev.get(k, 0)}" for k in
                                   ("critical", "high", "medium", "low", "info")))
    raw(f"{Colors.PURPLE}{'─'*70}{Colors.RESET}")
    shown = rows if want else rows[:200]
    for sev, tid, name, tags in shown:
        raw(f"  [{sev:8s}] {tid:42s} {name[:50]}  <{tags}>")
    if not want and len(rows) > 200:
        raw(f"  …（共 {len(rows)} 条，仅显示前 200 条，"
            f"可用 --poc-tags <tag> 进一步筛选）")
    else:
        raw(f"  共列出 {len(rows)} 条")
    return filtered
