"""
构建 PoC 模板库预解析索引（v12）
Author: 火柴 | GitHub: huocai250

把 pocs/nuclei 与 pocs/builtin 下的 YAML 模板解析为 pocs/index.json，
使运行时启动加载从「逐文件解析 YAML」变为「一次读 JSON」，大幅提速。
运行：
  cd webscanner && python tools/build_poc_index.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import yaml
except ImportError:
    print("[!] 需要 PyYAML: pip install PyYAML")
    sys.exit(1)


def walk_yaml(d):
    out = []
    for base, _, files in os.walk(d):
        for f in sorted(files):
            if f.endswith((".yaml", ".yml")):
                out.append(os.path.join(base, f))
    return out


def parse(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            data = list(yaml.safe_load_all(fh))
    except Exception:
        return []
    docs = []
    for d in data:
        if isinstance(d, dict):
            docs.append(d)
        elif isinstance(d, list):
            docs += [x for x in d if isinstance(x, dict)]
    return docs


def main():
    pocs = os.path.join(ROOT, "pocs")
    roots = [
        ("nuclei", os.path.join(pocs, "nuclei")),
        ("builtin", os.path.join(pocs, "builtin")),
    ]
    templates, seen, stats = [], set(), {"total": 0, "runnable": 0,
                                          "severity": {}, "sources": {}}
    for label, root in roots:
        if not os.path.isdir(root):
            continue
        for path in walk_yaml(root):
            for tpl in parse(path):
                if not isinstance(tpl, dict) or not tpl.get("id"):
                    continue
                if tpl["id"] in seen:
                    continue
                seen.add(tpl["id"])
                rel = os.path.relpath(path, pocs).replace("\\", "/")
                tpl["_source"] = rel
                reqs = tpl.get("http") or tpl.get("requests") or []
                if any(isinstance(r, dict) and (r.get("method") or r.get("path")
                                                or r.get("paths") or r.get("raw"))
                       for r in reqs):
                    stats["runnable"] += 1
                sev = str((tpl.get("info") or {}).get("severity", "info")).lower()
                stats["severity"][sev] = stats["severity"].get(sev, 0) + 1
                stats["sources"][label] = stats["sources"].get(label, 0) + 1
                templates.append(tpl)
    stats["total"] = len(templates)

    out = {"generated": __import__("datetime").datetime.now().isoformat(),
           "count": len(templates), "templates": templates}
    idx = os.path.join(pocs, "index.json")
    with open(idx, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
    with open(os.path.join(pocs, "STATS.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"index.json: {len(templates)} templates, "
          f"{os.path.getsize(idx)/1024/1024:.1f} MB")
    print("stats:", json.dumps(stats, ensure_ascii=False))


if __name__ == "__main__":
    main()
