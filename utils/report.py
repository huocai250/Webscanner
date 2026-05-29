"""
报告生成模块（支持终端 / JSON / HTML）
Author: 火柴 | GitHub: huocai250

修复:
- HTML 输出字段缺少转义（detail/evidence 可能含 XSS）
- 添加 html.escape 对所有用户数据转义
"""
import json
import html as html_mod
from datetime import datetime
from core.colors import Colors
from core.result import ScanResult


def _e(s: str) -> str:
    """HTML 转义，防止 report 自身被注入"""
    return html_mod.escape(str(s), quote=True)


def print_terminal(result: ScanResult):
    counts = result.summary()
    total = sum(counts.values())
    print(f"\n{Colors.BOLD}{'═'*65}{Colors.RESET}")
    print(f"{Colors.BOLD}  扫描报告  |  {result.target}{Colors.RESET}")
    print(f"{'═'*65}")
    print(f"  开始时间 : {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  耗    时 : {result.elapsed()}")
    print(f"  发现总数 : {total}")
    print(f"  风险分布 : "
          f"{Colors.RED}CRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}{Colors.RESET}  "
          f"{Colors.YELLOW}MEDIUM:{counts['MEDIUM']}{Colors.RESET}  "
          f"{Colors.BLUE}LOW:{counts['LOW']}{Colors.RESET}  "
          f"INFO:{counts['INFO']}")
    print(f"{'═'*65}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = result.by_severity(sev)
        if not items:
            continue
        color = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH":     Colors.RED,
            "MEDIUM":   Colors.YELLOW,
            "LOW":      Colors.BLUE,
            "INFO":     Colors.CYAN,
        }[sev]
        print(f"{color}▶ {sev} ({len(items)}){Colors.RESET}")
        for item in items:
            print(f"  {Colors.DIM}[{item.category}]{Colors.RESET} {item.detail}")
            if item.url:
                print(f"    {Colors.DIM}URL     : {item.url}{Colors.RESET}")
            if item.evidence:
                ev = str(item.evidence)[:120]
                print(f"    {Colors.DIM}Evidence: {ev}{Colors.RESET}")
        print()


def save_json(result: ScanResult, path: str):
    data = {
        "meta": {
            "tool":    "WebVulnScanner v4.0",
            "author":  "火柴",
            "github":  "https://github.com/huocai250",
            "target":  result.target,
            "scan_time": result.start_time.isoformat(),
            "elapsed": result.elapsed(),
        },
        "summary":  result.summary(),
        "findings": [f.to_dict() for f in result.findings],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"{Colors.GREEN}[+] JSON 报告已保存: {path}{Colors.RESET}")


def save_html(result: ScanResult, path: str):
    counts = result.summary()

    sev_color = {
        "CRITICAL": "#ff2222", "HIGH": "#ff7700",
        "MEDIUM":   "#ffcc00", "LOW":  "#44aaff", "INFO": "#aaaaaa"
    }

    rows = ""
    for f in result.findings:
        color   = sev_color.get(f.severity, "#aaa")
        detail  = _e(f.detail)
        evidence = _e(str(f.evidence)[:120]) if f.evidence else "-"
        url_cell = f'<a href="{_e(f.url)}" target="_blank">{_e(f.url)}</a>' if f.url else "-"
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{_e(f.severity)}</span></td>
          <td>{_e(f.category)}</td>
          <td>{detail}</td>
          <td class="mono">{url_cell}</td>
          <td class="mono small">{evidence}</td>
        </tr>"""

    stat_cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c   = counts[sev]
        col = sev_color[sev]
        stat_cards += (
            f'<div class="card" style="border-top:3px solid {col}">'
            f'<div class="cnt" style="color:{col}">{c}</div>'
            f'<div class="lbl">{sev}</div></div>'
        )

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>扫描报告 — {_e(result.target)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9}}
  header{{background:#161b22;padding:24px 40px;border-bottom:1px solid #30363d}}
  header h1{{color:#58a6ff;font-size:1.6em}}
  header p{{color:#8b949e;font-size:.9em;margin-top:4px}}
  .stats{{display:flex;gap:16px;padding:24px 40px;flex-wrap:wrap}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
         padding:16px 24px;min-width:110px;text-align:center}}
  .cnt{{font-size:2em;font-weight:700}}
  .lbl{{font-size:.8em;color:#8b949e;margin-top:4px}}
  .section{{padding:0 40px 40px}}
  table{{width:100%;border-collapse:collapse;background:#161b22;
         border:1px solid #30363d;border-radius:8px;overflow:hidden}}
  th{{background:#21262d;padding:12px 16px;text-align:left;
      font-size:.85em;color:#8b949e;border-bottom:1px solid #30363d}}
  td{{padding:10px 16px;border-bottom:1px solid #21262d;font-size:.9em;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1c2128}}
  .badge{{padding:2px 8px;border-radius:4px;font-size:.75em;
          font-weight:700;color:#000;white-space:nowrap}}
  .mono{{font-family:monospace;font-size:.82em;word-break:break-all}}
  .small{{font-size:.78em;color:#8b949e}}
  footer{{text-align:center;padding:24px;color:#484f58;font-size:.8em}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
</style>
</head>
<body>
<header>
  <h1>🔍 WebVulnScanner v4.0 — 扫描报告</h1>
  <p>目标: <strong>{_e(result.target)}</strong> &nbsp;|&nbsp;
     时间: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
     耗时: {result.elapsed()} &nbsp;|&nbsp;
     作者: <a href="https://github.com/huocai250" target="_blank">火柴 @huocai250</a></p>
</header>
<div class="stats">{stat_cards}</div>
<div class="section">
  <table>
    <thead><tr>
      <th>等级</th><th>类别</th><th>描述</th><th>URL</th><th>证据</th>
    </tr></thead>
    <tbody>{rows if rows else "<tr><td colspan='5' style='text-align:center;color:#8b949e;padding:32px'>未发现漏洞</td></tr>"}</tbody>
  </table>
</div>
<footer>Generated by WebVulnScanner v4.0 &nbsp;·&nbsp;
Author: 火柴 &nbsp;·&nbsp;
<a href="https://github.com/huocai250">GitHub: huocai250</a></footer>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{Colors.GREEN}[+] HTML 报告已保存: {path}{Colors.RESET}")
