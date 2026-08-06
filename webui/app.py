"""
Web UI（Flask + SSE 实时进度）
Author: 火柴 | GitHub: huocai250

启动： python -m webscanner.webui.app        （或 python webui/app.py）
       然后浏览器打开 http://127.0.0.1:5000

依赖： pip install flask
说明： 仅供本地授权测试使用；界面上仍会要求你确认已获授权。
"""
import os
import sys
import json
import queue
import threading
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from flask import Flask, request, Response, jsonify
except ImportError:
    print("需要 Flask：pip install flask")
    sys.exit(1)

from core.config import ScanConfig
from core.engine import run_scan
from utils.report import save_html

app = Flask(__name__)

# scan_id -> {"q": Queue, "result": ScanResult|None, "done": bool}
SCANS = {}

PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebVulnScanner v8</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--mut:#8b949e;
--acc:#58a6ff;--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#3fb950;--info:#8b949e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:-apple-system,Segoe UI,Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:18px;margin-bottom:16px}
label{display:block;font-size:12px;color:var(--mut);margin:8px 0 4px}
input[type=text]{width:100%;background:#0d1117;border:1px solid var(--border);
color:var(--fg);border-radius:6px;padding:9px 11px;font-size:14px}
.row{display:flex;gap:16px;flex-wrap:wrap}.row>div{flex:1;min-width:120px}
.opts{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:13px}
.opts label{display:flex;align-items:center;gap:6px;color:var(--fg);margin:0}
button{background:var(--acc);color:#04101f;border:0;border-radius:6px;
padding:10px 18px;font-size:14px;font-weight:600;cursor:pointer;margin-top:14px}
button:disabled{opacity:.5;cursor:not-allowed}
.bar{height:8px;background:#0d1117;border-radius:4px;overflow:hidden;margin:12px 0}
.bar>i{display:block;height:100%;width:0;background:var(--acc);transition:width .3s}
.status{font-size:13px;color:var(--mut)}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--border);
vertical-align:top}th{color:var(--mut);font-weight:500}
.sev{font-weight:700;font-size:11px;padding:2px 7px;border-radius:20px}
.CRITICAL{color:var(--crit);border:1px solid var(--crit)}
.HIGH{color:var(--high);border:1px solid var(--high)}
.MEDIUM{color:var(--med);border:1px solid var(--med)}
.LOW{color:var(--low);border:1px solid var(--low)}
.INFO{color:var(--info);border:1px solid var(--info)}
.evi{color:var(--mut);font-family:ui-monospace,monospace;font-size:11px;word-break:break-all}
.warn{background:#3d2f14;border:1px solid #d29922;color:#e3b341;padding:10px 12px;
border-radius:6px;font-size:12px;margin-bottom:14px}
a{color:var(--acc)}
</style></head><body><div class="wrap">
<h1>🛡️ WebVulnScanner v8</h1>
<div class="sub">检测/评估型扫描器 · 仅供授权渗透测试使用</div>
<div class="warn">⚠ 请确认你已获得目标系统的书面授权。未授权扫描属于违法行为。</div>
<div class="card">
  <label>目标 URL</label>
  <input type="text" id="target" placeholder="https://example.com">
  <div class="row">
    <div><label>线程</label><input type="text" id="threads" value="10"></div>
    <div><label>速率(req/s，0=不限)</label><input type="text" id="rate" value="0"></div>
    <div><label>最大爬取页面</label><input type="text" id="maxurls" value="50"></div>
  </div>
  <div class="opts">
    <label><input type="checkbox" id="passive"> 被动模式</label>
    <label><input type="checkbox" id="authorized"> 我已获得授权</label>
  </div>
  <button id="go" onclick="startScan()">开始扫描</button>
</div>
<div class="card" id="progress" style="display:none">
  <div class="status" id="status">准备中…</div>
  <div class="bar"><i id="fill"></i></div>
  <div id="summary" class="status"></div>
  <div id="report"></div>
  <table id="tbl"><thead><tr><th>等级</th><th>类别</th><th>问题</th><th>URL</th></tr>
  </thead><tbody id="rows"></tbody></table>
</div>
<script>
function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;',
'>':'&gt;','"':'&quot;'}[c]));}
function startScan(){
  const t=document.getElementById('target').value.trim();
  if(!t){alert('请输入目标 URL');return;}
  if(!document.getElementById('authorized').checked){alert('请先勾选“我已获得授权”');return;}
  document.getElementById('go').disabled=true;
  document.getElementById('progress').style.display='block';
  document.getElementById('rows').innerHTML='';
  document.getElementById('report').innerHTML='';
  fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:t,threads:+document.getElementById('threads').value,
    rate:+document.getElementById('rate').value,max_urls:+document.getElementById('maxurls').value,
    passive:document.getElementById('passive').checked})})
   .then(r=>r.json()).then(d=>{listen(d.id);})
   .catch(e=>{alert('启动失败:'+e);document.getElementById('go').disabled=false;});
}
function listen(id){
  const es=new EventSource('/stream/'+id);
  es.onmessage=ev=>{
    const d=JSON.parse(ev.data);
    if(d.type==='progress'){
      document.getElementById('status').textContent=
        '['+d.done+'/'+d.total+'] '+d.module+' · 已发现 '+d.findings+' 项';
      document.getElementById('fill').style.width=(100*d.done/d.total)+'%';
    }else if(d.type==='done'){
      es.close();document.getElementById('go').disabled=false;
      document.getElementById('status').textContent='扫描完成';
      document.getElementById('fill').style.width='100%';
      render(d);
    }
  };
  es.onerror=()=>{es.close();document.getElementById('go').disabled=false;};
}
function render(d){
  document.getElementById('summary').innerHTML='风险评分 <b>'+d.score+'/100</b> ['+d.grade+
    '] · 发现 '+d.total_findings+' 项 · 耗时 '+d.elapsed+' · 请求 '+d.requests;
  if(d.report_url){document.getElementById('report').innerHTML=
    '<p>📄 <a href="'+d.report_url+'" target="_blank">查看完整 HTML 报告</a></p>';}
  const rows=document.getElementById('rows');rows.innerHTML='';
  d.findings.forEach(f=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td><span class="sev '+f.severity+'">'+f.severity+'</span></td>'+
      '<td>'+esc(f.category)+'</td><td>'+esc(f.detail)+
      (f.evidence?'<div class="evi">'+esc(f.evidence)+'</div>':'')+'</td>'+
      '<td class="evi">'+esc(f.url)+'</td>';
    rows.appendChild(tr);
  });
}
</script></div></body></html>"""


@app.route("/")
def index():
    return PAGE


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "缺少目标"}), 400

    cfg = ScanConfig(
        target=target,
        threads=int(data.get("threads", 10)),
        rate=float(data.get("rate", 0)),
        max_urls=int(data.get("max_urls", 50)),
        passive=bool(data.get("passive", False)),
        skip={"subdomain"},   # Web UI 默认跳过子域名枚举（耗时）
    )
    sid = uuid.uuid4().hex[:12]
    q = queue.Queue()
    SCANS[sid] = {"q": q, "result": None, "done": False}

    def progress(cn, done, total, findings):
        q.put({"type": "progress", "module": cn, "done": done,
               "total": total, "findings": findings})

    def worker():
        try:
            res = run_scan(cfg, progress=progress, verbose=False)
            SCANS[sid]["result"] = res
            report_url = None
            try:
                os.makedirs("webui_reports", exist_ok=True)
                path = os.path.join("webui_reports", f"report_{sid}.html")
                save_html(res, path)
                report_url = "/report/" + sid
            except Exception:
                pass
            q.put({"type": "done", "score": res.risk_score(),
                   "grade": res.risk_grade(), "elapsed": res.elapsed(),
                   "requests": res.request_count,
                   "total_findings": len(res.findings),
                   "report_url": report_url,
                   "findings": [f.to_dict() for f in res.findings]})
        except Exception as e:
            q.put({"type": "done", "score": 0, "grade": "错误",
                   "elapsed": "-", "requests": 0, "total_findings": 0,
                   "report_url": None, "findings": [],
                   "error": str(e)})
        finally:
            SCANS[sid]["done"] = True
            q.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"id": sid})


@app.route("/stream/<sid>")
def stream(sid):
    if sid not in SCANS:
        return "not found", 404
    q = SCANS[sid]["q"]

    def gen():
        while True:
            item = q.get()
            if item is None:
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
    return Response(gen(), mimetype="text/event-stream")


@app.route("/report/<sid>")
def report(sid):
    path = os.path.join("webui_reports", f"report_{sid}.html")
    if not os.path.exists(path):
        return "报告不存在", 404
    with open(path, encoding="utf-8") as f:
        return f.read()


def main():
    host = os.environ.get("WVS_HOST", "127.0.0.1")
    port = int(os.environ.get("WVS_PORT", "5000"))
    print(f"[*] WebVulnScanner Web UI -> http://{host}:{port}")
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
