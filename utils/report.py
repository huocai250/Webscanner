"""
报告生成模块（终端 / JSON / HTML / Markdown / CSV）
Author: 火柴 | GitHub: huocai250

v4.0 改进：
  - HTML 报告全字段转义（修复报告自身可被注入的问题）
  - 增加风险评分/等级、按严重程度分组、每类修复建议、置信度
  - 新增 Markdown 与 CSV 导出
"""
import csv
import json
import html
from datetime import datetime
from core.colors import Colors, raw
from core.result import ScanResult
from core import remediation

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLOR = {
    "CRITICAL": "#ff4444", "HIGH": "#ff7700",
    "MEDIUM": "#ffcc00", "LOW": "#44aaff", "INFO": "#8b949e",
}
GRADE_COLOR = {"严重": "#ff4444", "高危": "#ff7700", "中危": "#ffcc00",
               "低危": "#44aaff", "良好": "#3fb950"}


# ---------------------------------------------------------------- 终端
def print_terminal(result: ScanResult):
    counts = result.summary()
    total = sum(counts.values())
    score = result.risk_score()
    grade = result.risk_grade()

    raw(f"\n{Colors.BOLD}{'═'*65}{Colors.RESET}")
    raw(f"{Colors.BOLD}  扫描报告  |  {result.target}{Colors.RESET}")
    raw(f"{'═'*65}")
    raw(f"  开始时间 : {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    raw(f"  耗时     : {result.elapsed()}   |   请求数: {result.request_count}")
    raw(f"  风险评分 : {Colors.BOLD}{score}/100  [{grade}]{Colors.RESET}")
    raw(f"  发现总数 : {total}")
    raw(f"  风险分布 : "
        f"{Colors.RED}CRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}{Colors.RESET}  "
        f"{Colors.YELLOW}MEDIUM:{counts['MEDIUM']}{Colors.RESET}  "
        f"{Colors.BLUE}LOW:{counts['LOW']}{Colors.RESET}  "
        f"INFO:{counts['INFO']}")
    raw(f"{'═'*65}\n")

    for sev in SEV_ORDER:
        items = result.by_severity(sev)
        if not items:
            continue
        color = {
            "CRITICAL": Colors.RED + Colors.BOLD, "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW, "LOW": Colors.BLUE, "INFO": Colors.CYAN,
        }[sev]
        raw(f"{color}▶ {sev} ({len(items)}){Colors.RESET}")
        for item in items:
            conf = f" {Colors.DIM}({item.confidence}){Colors.RESET}" if item.confidence != "确认" else ""
            raw(f"  {Colors.DIM}[{item.category}]{Colors.RESET} {item.detail}{conf}")
            if item.url:
                raw(f"    {Colors.DIM}URL     : {item.url}{Colors.RESET}")
            if item.evidence:
                raw(f"    {Colors.DIM}Evidence: {str(item.evidence)[:120]}{Colors.RESET}")
        raw("")


# ---------------------------------------------------------------- JSON
def save_json(result: ScanResult, path: str):
    data = {
        "meta": {
            "tool": "WebVulnScanner v4.0",
            "author": "火柴",
            "github": "https://github.com/huocai250",
            "target": result.target,
            "scan_time": result.start_time.isoformat(),
            "elapsed": result.elapsed(),
            "requests": result.request_count,
            "risk_score": result.risk_score(),
            "risk_grade": result.risk_grade(),
        },
        "summary": result.summary(),
        "findings": [
            {**f.to_dict(), "remediation": remediation.get(f.category)}
            for f in result.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    raw(f"{Colors.GREEN}[+] JSON 报告已保存: {path}{Colors.RESET}")


# ---------------------------------------------------------------- CSV
def save_csv(result: ScanResult, path: str):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity", "confidence", "category", "detail", "url",
                    "evidence", "remediation", "time"])
        for fd in result.findings:
            w.writerow([fd.severity, fd.confidence, fd.category, fd.detail,
                        fd.url, str(fd.evidence)[:300],
                        remediation.get(fd.category), fd.time])
    raw(f"{Colors.GREEN}[+] CSV 报告已保存: {path}{Colors.RESET}")


# ---------------------------------------------------------------- Markdown
def save_markdown(result: ScanResult, path: str):
    counts = result.summary()
    lines = [
        f"# WebVulnScanner v4.0 扫描报告",
        "",
        f"- **目标**: {result.target}",
        f"- **时间**: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **耗时**: {result.elapsed()}  |  **请求数**: {result.request_count}",
        f"- **风险评分**: {result.risk_score()}/100  （{result.risk_grade()}）",
        f"- **风险分布**: CRITICAL {counts['CRITICAL']} · HIGH {counts['HIGH']} · "
        f"MEDIUM {counts['MEDIUM']} · LOW {counts['LOW']} · INFO {counts['INFO']}",
        "",
    ]
    for sev in SEV_ORDER:
        items = result.by_severity(sev)
        if not items:
            continue
        lines.append(f"## {sev} ({len(items)})\n")
        seen_cat = set()
        for it in items:
            conf = f" _{it.confidence}_" if it.confidence != "确认" else ""
            lines.append(f"### [{it.category}] {it.detail}{conf}")
            if it.url:
                lines.append(f"- URL: `{it.url}`")
            if it.evidence:
                lines.append(f"- 证据: `{str(it.evidence)[:200]}`")
            if it.category not in seen_cat:
                lines.append(f"- 修复建议: {remediation.get(it.category)}")
                seen_cat.add(it.category)
            lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    raw(f"{Colors.GREEN}[+] Markdown 报告已保存: {path}{Colors.RESET}")


# ---------------------------------------------------------------- HTML
def _e(x) -> str:
    """HTML 转义（所有动态内容必须经过此函数）。"""
    return html.escape(str(x), quote=True)


def save_html(result: ScanResult, path: str):
    counts = result.summary()
    score = result.risk_score()
    grade = result.risk_grade()
    gcol = GRADE_COLOR.get(grade, "#8b949e")

    # 统计卡片
    stat_cards = ""
    for sev in SEV_ORDER:
        col = SEV_COLOR[sev]
        stat_cards += (
            f'<div class="card" style="border-top:3px solid {col}">'
            f'<div class="cnt" style="color:{col}">{counts[sev]}</div>'
            f'<div class="lbl">{sev}</div></div>'
        )

    # 按严重程度分组的区块
    sections = ""
    for sev in SEV_ORDER:
        items = result.by_severity(sev)
        if not items:
            continue
        col = SEV_COLOR[sev]
        rows = ""
        cat_seen = set()
        for f in items:
            conf = "" if f.confidence == "确认" else f' <span class="conf">{_e(f.confidence)}</span>'
            rem = ""
            if f.category not in cat_seen:
                rem = f'<div class="rem">🛠 修复建议：{_e(remediation.get(f.category))}</div>'
                cat_seen.add(f.category)
            rows += f"""
            <tr>
              <td class="cat">{_e(f.category)}</td>
              <td>{_e(f.detail)}{conf}
                  {f'<div class="evi">{_e(str(f.evidence)[:200])}</div>' if f.evidence else ''}
                  {rem}</td>
              <td class="mono">{_e(f.url) or '-'}</td>
            </tr>"""
        sections += f"""
        <div class="sev-block">
          <h2 style="color:{col}">▶ {sev} <span class="count">{len(items)}</span></h2>
          <table>
            <thead><tr><th style="width:15%">类别</th><th>描述 / 修复建议</th><th style="width:26%">URL</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    if not sections:
        sections = '<p class="empty">未发现任何问题。</p>'

    # 风险仪表（signature 元素）：环形进度
    circ = 2 * 3.14159 * 52
    dash = circ * (score / 100)

    html_doc = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>扫描报告 - {_e(result.target)}</title>
<style>
  :root {{ --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#c9d1d9; --dim:#8b949e; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',system-ui,Arial,sans-serif; background:var(--bg); color:var(--fg); line-height:1.5; }}
  header {{ background:var(--panel); padding:24px 40px; border-bottom:1px solid var(--border);
            display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:24px; }}
  .htext h1 {{ color:#58a6ff; font-size:1.5em; letter-spacing:.5px; }}
  .htext p {{ color:var(--dim); font-size:.88em; margin-top:6px; }}
  .htext a {{ color:#58a6ff; text-decoration:none; }}
  .gauge {{ position:relative; width:132px; height:132px; flex-shrink:0; }}
  .gauge svg {{ transform:rotate(-90deg); }}
  .gauge .val {{ position:absolute; inset:0; display:flex; flex-direction:column;
                 align-items:center; justify-content:center; }}
  .gauge .num {{ font-size:2em; font-weight:800; color:{gcol}; }}
  .gauge .grd {{ font-size:.8em; color:var(--dim); margin-top:2px; }}
  .stats {{ display:flex; gap:16px; padding:24px 40px; flex-wrap:wrap; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:8px;
           padding:14px 22px; min-width:104px; text-align:center; }}
  .cnt {{ font-size:1.9em; font-weight:700; }}
  .lbl {{ font-size:.78em; color:var(--dim); margin-top:2px; letter-spacing:1px; }}
  main {{ padding:0 40px 48px; }}
  .sev-block {{ margin-bottom:34px; }}
  .sev-block h2 {{ font-size:1.05em; margin-bottom:12px; letter-spacing:.5px; }}
  .sev-block h2 .count {{ color:var(--dim); font-size:.8em; font-weight:400; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel);
           border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
  th {{ background:#21262d; padding:11px 16px; text-align:left; font-size:.82em;
        color:var(--dim); border-bottom:1px solid var(--border); font-weight:600; }}
  td {{ padding:12px 16px; border-bottom:1px solid #21262d; font-size:.9em; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  tr:hover td {{ background:#1c2128; }}
  .cat {{ color:#79c0ff; font-weight:600; white-space:nowrap; }}
  .conf {{ font-size:.75em; color:#d29922; border:1px solid #d29922; border-radius:4px;
           padding:0 5px; margin-left:6px; }}
  .evi {{ font-family:ui-monospace,Consolas,monospace; font-size:.8em; color:var(--dim);
          margin-top:6px; word-break:break-all; background:#0d1117; padding:6px 8px;
          border-radius:5px; border:1px solid var(--border); }}
  .rem {{ margin-top:8px; font-size:.84em; color:#3fb950; border-left:2px solid #3fb950;
          padding-left:10px; }}
  .mono {{ font-family:ui-monospace,Consolas,monospace; font-size:.82em; word-break:break-all; color:var(--dim); }}
  .empty {{ padding:40px; text-align:center; color:var(--dim); }}
  footer {{ text-align:center; padding:24px; color:#484f58; font-size:.8em; border-top:1px solid var(--border); }}
  footer a {{ color:#58a6ff; text-decoration:none; }}
  @media (max-width:640px) {{ header,.stats,main {{ padding-left:18px; padding-right:18px; }} }}
</style>
</head>
<body>
<header>
  <div class="htext">
    <h1>🔍 WebVulnScanner v4.0 — 扫描报告</h1>
    <p>目标: <strong>{_e(result.target)}</strong> &nbsp;|&nbsp;
       时间: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
       耗时: {result.elapsed()} &nbsp;|&nbsp; 请求: {result.request_count} &nbsp;|&nbsp;
       作者: <a href="https://github.com/huocai250" target="_blank" rel="noopener">火柴 @huocai250</a></p>
  </div>
  <div class="gauge">
    <svg width="132" height="132">
      <circle cx="66" cy="66" r="52" fill="none" stroke="#21262d" stroke-width="10"/>
      <circle cx="66" cy="66" r="52" fill="none" stroke="{gcol}" stroke-width="10"
              stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"/>
    </svg>
    <div class="val"><span class="num">{score}</span><span class="grd">{grade} · /100</span></div>
  </div>
</header>
<div class="stats">{stat_cards}</div>
<main>{sections}</main>
<footer>Generated by WebVulnScanner v4.0 · Author: 火柴 ·
  <a href="https://github.com/huocai250">GitHub</a> ·
  仅供授权渗透测试与安全研究使用</footer>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    raw(f"{Colors.GREEN}[+] HTML 报告已保存: {path}{Colors.RESET}")
