"""
报告生成模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[新增] CSV 格式输出
[优化] HTML 报告：加入利用结果列、漏洞统计图
[修复] 所有字段 HTML 转义防止 XSS
"""
import json
import csv
import html as html_mod
import logging
from datetime import datetime
from pathlib import Path
from core.result import ScanResult
from core.logger import C

log = logging.getLogger("webscan")


def _esc(s) -> str:
    """HTML 转义"""
    return html_mod.escape(str(s), quote=True)


# ── 终端输出 ──────────────────────────────────────────────────
def print_terminal(result: ScanResult):
    counts = result.summary()
    total  = result.total()
    print(f"\n{C.BOLD}{'═'*70}{C.RESET}")
    print(f"{C.BOLD}  WebVulnScanner v6.0 扫描报告  |  {result.target}{C.RESET}")
    print(f"{'═'*70}")
    print(f"  目    标 : {result.target}")
    print(f"  开始时间 : {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  耗    时 : {result.elapsed()}")
    print(f"  发现总数 : {total}")
    print(f"  风险分布 : "
          f"{C.RED}{C.BOLD}CRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}{C.RESET}  "
          f"{C.YELLOW}MEDIUM:{counts['MEDIUM']}{C.RESET}  "
          f"{C.BLUE}LOW:{counts['LOW']}{C.RESET}  "
          f"INFO:{counts['INFO']}")
    print(f"{'═'*70}\n")

    sev_colors = {
        "CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
        "MEDIUM":   C.YELLOW,       "LOW":  C.BLUE, "INFO": C.CYAN,
    }
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = result.by_severity(sev)
        if not items:
            continue
        color = sev_colors[sev]
        print(f"{color}▶ {sev} ({len(items)}){C.RESET}")
        for item in items:
            print(f"  {C.DIM}[{item.category}]{C.RESET} {item.detail}")
            if item.url:
                print(f"    {C.DIM}URL     : {item.url}{C.RESET}")
            if item.evidence:
                print(f"    {C.DIM}Evidence: {str(item.evidence)[:120]}{C.RESET}")
            if item.exploit_result:
                print(f"    {C.GREEN}利用结果: {item.exploit_result[:200]}{C.RESET}")
        print()


# ── JSON ─────────────────────────────────────────────────────
def save_json(result: ScanResult, path: str):
    data = {
        "meta": {
            "tool":      "WebVulnScanner v6.0",
            "author":    "火柴",
            "github":    "https://github.com/huocai250",
            "target":    result.target,
            "scan_time": result.start_time.isoformat(),
            "elapsed":   result.elapsed(),
        },
        "summary":  result.summary(),
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }
    _write(path, lambda f: json.dump(data, f, ensure_ascii=False, indent=2))
    log.info(f"JSON 报告已保存: {path}")


# ── CSV [新增] ────────────────────────────────────────────────
def save_csv(result: ScanResult, path: str):
    """[新增] CSV 格式报告，便于导入 Excel / 数据库"""
    headers = ["时间戳", "严重级别", "类别", "描述", "URL", "证据", "利用结果"]
    rows = [f.to_csv_row() for f in result.sorted_findings()]

    def _write_csv(f):
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)

    _write(path, _write_csv, mode="w", encoding="utf-8-sig")  # utf-8-sig for Excel
    log.info(f"CSV 报告已保存: {path}")


# ── HTML ─────────────────────────────────────────────────────
def save_html(result: ScanResult, path: str):
    counts = result.summary()
    sev_color = {
        "CRITICAL": "#ff2222", "HIGH": "#ff7700",
        "MEDIUM":   "#ffcc00", "LOW":  "#44aaff", "INFO": "#aaaaaa",
    }

    # 统计卡片
    stat_cards = "".join(
        f'<div class="card" style="border-top:3px solid {sev_color[s]}">'
        f'<div class="cnt" style="color:{sev_color[s]}">{counts[s]}</div>'
        f'<div class="lbl">{s}</div></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    # 表格行
    rows = ""
    for f in result.sorted_findings():
        col   = sev_color.get(f.severity, "#aaa")
        xr    = _esc(f.exploit_result[:300]) if f.exploit_result else "-"
        extra = ""
        if f.extra:
            extra = "<br>".join(f"{_esc(k)}: {_esc(str(v)[:200])}"
                                for k, v in f.extra.items())
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{col}">{_esc(f.severity)}</span></td>
          <td>{_esc(f.category)}</td>
          <td>{_esc(f.detail)}</td>
          <td class="mono">{f'<a href="{_esc(f.url)}" target="_blank">{_esc(f.url)}</a>' if f.url else '-'}</td>
          <td class="mono small">{_esc(str(f.evidence)[:150]) if f.evidence else '-'}</td>
          <td class="exploit">{xr}</td>
          <td class="small">{extra or '-'}</td>
          <td class="small">{_esc(f.timestamp[:19])}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>扫描报告 — {_esc(result.target)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:14px}}
  header{{background:#161b22;padding:20px 32px;border-bottom:1px solid #30363d}}
  header h1{{color:#58a6ff;font-size:1.5em;margin-bottom:4px}}
  header p{{color:#8b949e;font-size:.9em}}
  .stats{{display:flex;gap:12px;padding:20px 32px;flex-wrap:wrap}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 20px;min-width:100px;text-align:center}}
  .cnt{{font-size:2em;font-weight:700}}
  .lbl{{font-size:.75em;color:#8b949e;margin-top:2px}}
  .section{{padding:0 32px 32px}}
  .filter-bar{{padding:0 32px 12px;display:flex;gap:8px;flex-wrap:wrap}}
  .filter-btn{{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:4px 12px;
               border-radius:4px;cursor:pointer;font-size:.8em}}
  .filter-btn.active{{background:#58a6ff;color:#000}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}}
  th{{background:#21262d;padding:10px 12px;text-align:left;font-size:.8em;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap}}
  td{{padding:8px 12px;border-bottom:1px solid #21262d;font-size:.85em;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1c2128}}
  .badge{{padding:2px 8px;border-radius:4px;font-size:.7em;font-weight:700;color:#000;white-space:nowrap}}
  .mono{{font-family:monospace;font-size:.8em;word-break:break-all}}
  .small{{font-size:.78em;color:#8b949e}}
  .exploit{{font-family:monospace;font-size:.8em;color:#7ee787;word-break:break-all}}
  footer{{text-align:center;padding:20px;color:#484f58;font-size:.8em}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .hidden{{display:none}}
</style>
</head>
<body>
<header>
  <h1>🔍 WebVulnScanner v6.0 — 扫描报告</h1>
  <p>目标: <strong>{_esc(result.target)}</strong> &nbsp;|&nbsp;
     时间: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
     耗时: {result.elapsed()} &nbsp;|&nbsp;
     作者: <a href="https://github.com/huocai250" target="_blank">火柴 @huocai250</a></p>
</header>
<div class="stats">{stat_cards}</div>
<div class="filter-bar">
  <span style="color:#8b949e;font-size:.85em;line-height:28px">筛选:</span>
  {''.join(f'<button class="filter-btn active" onclick="toggleFilter(this,\'{s}\')">{s}</button>'
           for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])}
</div>
<div class="section">
  <table id="main-table">
    <thead><tr>
      <th>等级</th><th>类别</th><th>描述</th><th>URL</th>
      <th>证据</th><th>利用结果</th><th>额外信息</th><th>时间</th>
    </tr></thead>
    <tbody>{rows or "<tr><td colspan='8' style='text-align:center;color:#8b949e;padding:32px'>未发现漏洞</td></tr>"}</tbody>
  </table>
</div>
<footer>
  WebVulnScanner v6.0 &nbsp;·&nbsp; 作者: 火柴 &nbsp;·&nbsp;
  <a href="https://github.com/huocai250">GitHub: huocai250</a>
</footer>
<script>
function toggleFilter(btn, sev) {{
  btn.classList.toggle('active');
  const active = [...document.querySelectorAll('.filter-btn.active')].map(b => b.textContent);
  document.querySelectorAll('#main-table tbody tr').forEach(row => {{
    const badge = row.querySelector('.badge');
    if (!badge) return;
    row.classList.toggle('hidden', !active.includes(badge.textContent));
  }});
}}
</script>
</body>
</html>"""

    _write(path, lambda f: f.write(html))
    log.info(f"HTML 报告已保存: {path}")


def _write(path: str, writer_fn, mode: str = "w", encoding: str = "utf-8"):
    """[优化] 统一文件写入，含异常处理"""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, mode, encoding=encoding) as f:
            writer_fn(f)
    except OSError as e:
        log.error(f"无法写入报告 {path}: {e}")
