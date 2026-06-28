"""
Web UI — WebVulnScanner v7.0
Author: 火柴 | GitHub: huocai250

[新增] Flask Web 界面
  - 实时扫描进度（SSE 事件流）
  - 在线查看扫描报告
  - 支持多目标批量扫描
  - API 接口
"""
import sys
import os
import json
import time
import threading
import logging
from datetime import datetime
from pathlib import Path

# 确保项目根目录在 path 里
ROOT = str(Path(__file__).parent.parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from flask import Flask, render_template, request, Response, jsonify, stream_with_context
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

log = logging.getLogger("webscan")

app   = Flask(__name__) if HAS_FLASK else None
# [安全] 模块级限制，确保任何时候都生效
if app:
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
scans: dict = {}      # scan_id → {status, result, events}
_lock = threading.Lock()
MAX_SCANS = 100          # [优化] 最多保留扫描历史数，防止内存泄漏


def create_app():
    """应用工厂"""
    if not HAS_FLASK:
        raise ImportError("Flask 未安装，请运行: pip install flask")
    # [安全] 限制请求体大小：最大 1MB，防止恶意超大请求
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
    return app


# [新增] 全局错误处理
@app.errorhandler(404)
def not_found(e):
    return {"error": "路由不存在", "code": 404}, 404

@app.errorhandler(500)
def server_error(e):
    log.error(f"Flask 500: {e}")
    return {"error": "服务器内部错误", "code": 500}, 500

@app.errorhandler(413)
def too_large(e):
    return {"error": "请求体过大（最大 1MB）", "code": 413}, 413


# ── 页面路由 ──────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    """启动扫描任务"""
    data    = request.get_json() or request.form
    targets = data.get("targets", "").strip().splitlines()
    targets = [t.strip() for t in targets if t.strip()]

    if not targets:
        return jsonify({"error": "请提供至少一个目标"}), 400

    # 构建配置
    from core.config import ScanConfig
    cfg            = ScanConfig()
    cfg.exploit    = str(data.get("exploit", "false")).lower() == "true"
    cfg.fast_mode  = str(data.get("fast", "false")).lower() == "true"
    cfg.threads    = int(data.get("threads", 10))
    cfg.timeout    = int(data.get("timeout", 10))
    cfg.rate_limit = float(data.get("rate_limit", 0))

    exploit_types = data.get("exploit_types", "")
    cfg.exploit_types = [x.strip() for x in exploit_types.split(",") if x.strip()]

    skip_list = data.get("skip_modules", "").split(",")
    cfg.skip_ports     = "ports"    in skip_list
    cfg.skip_dirbust   = "dirbust"  in skip_list
    cfg.skip_sqli      = "sqli"     in skip_list
    cfg.skip_xss       = "xss"      in skip_list
    cfg.skip_lfi       = "lfi"      in skip_list
    cfg.skip_subdomain = "subdomain" in skip_list

    scan_id = f"scan_{int(time.time()*1000)}"
    with _lock:
        # [优化] 超出上限时删除最老的记录
        if len(scans) >= MAX_SCANS:
            oldest = min(scans, key=lambda k: scans[k]["started"])
            del scans[oldest]
        scans[scan_id] = {
            "id":       scan_id,
            "targets":  targets,
            "status":   "running",
            "started":  datetime.now().isoformat(),
            "finished": None,
            "events":   [],
            "results":  [],
            "cfg":      cfg,
        }

    # 后台线程运行扫描
    t = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, targets, cfg),
        daemon=True
    )
    t.start()

    return jsonify({"scan_id": scan_id, "message": f"扫描已启动，共 {len(targets)} 个目标"})


@app.route("/scan/<scan_id>/stream")
def scan_stream(scan_id: str):
    """SSE 实时进度流"""
    def generate():
        last_idx = 0
        while True:
            # [修复] 统一在锁内读取，避免并发修改
            with _lock:
                scan = scans.get(scan_id)
                if not scan:
                    yield f"data: {json.dumps({"type": "error", "message": "扫描不存在"})}\n\n"
                    return
                events   = list(scan["events"][last_idx:])  # 复制一份再解锁
                status   = scan["status"]
                last_idx = len(scan["events"])

            for ev in events:
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

            if status == "done":
                yield f"data: {json.dumps({'type':'done','scan_id':scan_id})}\n\n"
                return

            time.sleep(0.3)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering":"no",
        }
    )


@app.route("/scan/<scan_id>/result")
def scan_result(scan_id: str):
    """获取扫描结果"""
    with _lock:
        scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "扫描不存在"}), 404

    results = []
    for r in scan.get("results", []):
        results.append({
            "target":   r["target"],
            "elapsed":  r["elapsed"],
            "summary":  r["summary"],
            "findings": r["findings"],
        })

    return jsonify({
        "scan_id":  scan_id,
        "status":   scan["status"],
        "started":  scan["started"],
        "finished": scan["finished"],
        "results":  results,
    })


@app.route("/scans")
def list_scans():
    """列出所有扫描"""
    with _lock:
        summary = [{
            "id":      s["id"],
            "targets": s["targets"],
            "status":  s["status"],
            "started": s["started"],
        } for s in scans.values()]
    return jsonify(summary)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "v7.0"})


# ── 后台扫描线程 ──────────────────────────────────────────────

def _emit(scan_id: str, ev_type: str, **kwargs):
    """向 SSE 流推送事件"""
    ev = {"type": ev_type, "time": datetime.now().strftime("%H:%M:%S"), **kwargs}
    with _lock:
        if scan_id in scans:
            scans[scan_id]["events"].append(ev)


def _run_scan_thread(scan_id: str, targets: list, cfg):
    """后台扫描线程"""
    from core.scanner    import validate_url
    from core.rate_limiter import RateLimiter
    from core.result     import ScanResult
    from utils.http      import parse_cookies, parse_headers

    all_results = []

    for i, target in enumerate(targets, 1):
        try:
            target = validate_url(target)
        except ValueError as e:
            _emit(scan_id, "error", message=f"无效目标: {target}: {e}")
            continue

        _emit(scan_id, "target_start",
              target=target, index=i, total=len(targets))

        result = ScanResult(target)
        rl     = RateLimiter(cfg.rate_limit)
        kw     = dict(
            timeout=cfg.timeout, threads=cfg.threads,
            cookies={}, headers={}, proxy=cfg.proxy or None,
            rate_limiter=rl, max_retries=cfg.max_retries,
            user_agent=None, exploit_mode=cfg.exploit,
        )

        # 动态导入所有模块，与 main.py 保持一致
        from modules.info           import InfoGatherer
        from modules.fingerprint    import FingerprintScanner
        from modules.headers        import HeaderChecker
        from modules.ssl_check      import SSLChecker
        from modules.sensitive      import SensitiveInfoScanner
        from modules.cors           import CORSScanner
        from modules.csrf           import CSRFScanner
        from modules.sqli           import SQLiScanner
        from modules.xss            import XSSScanner
        from modules.lfi            import LFIScanner
        from modules.cms_scan       import CMSScanner
        from modules.api_security   import APIScanner

        fast = cfg.fast_mode
        plan = [
            ("info",    "信息收集",    InfoGatherer(target, result, **kw),    False),
            ("fp",      "指纹识别",    FingerprintScanner(target, result, **kw), False),
            ("headers", "HTTP安全头",  HeaderChecker(target, result, **kw),   False),
            ("ssl",     "SSL/TLS",     SSLChecker(target, result, **kw),      False),
            ("cms",     "CMS专项",     CMSScanner(target, result, **kw),      False),
            ("api",     "API安全",     APIScanner(target, result, **kw),      False),
            ("sensitive","敏感信息",   SensitiveInfoScanner(target, result, **kw), False),
            ("cors",    "CORS",        CORSScanner(target, result, **kw),     False),
            ("csrf",    "CSRF",        CSRFScanner(target, result, **kw),     False),
            ("sqli",    "SQL注入",     SQLiScanner(target, result, **kw),     cfg.skip_sqli),
            ("xss",     "XSS",         XSSScanner(target, result, **kw),      cfg.skip_xss),
            ("lfi",     "LFI/命令注入",LFIScanner(target, result, **kw),      cfg.skip_lfi),
        ]

        for key, label, module, skip in plan:
            if skip:
                continue
            _emit(scan_id, "module_start", target=target, module=label)
            try:
                module.run()
                count = result.total() - sum(
                    1 for f in result.findings
                    if f.category not in [label, "指纹识别", "信息收集"]
                )
                _emit(scan_id, "module_done", target=target, module=label)
            except Exception as e:
                _emit(scan_id, "module_error", target=target,
                      module=label, error=str(e))

            # 推送新发现
            for finding in result.findings[-5:]:
                if finding.severity in ("CRITICAL", "HIGH"):
                    _emit(scan_id, "vuln_found",
                          target=target,
                          severity=finding.severity,
                          category=finding.category,
                          detail=finding.detail,
                          url=finding.url)

        summary = result.summary()
        all_results.append({
            "target":   target,
            "elapsed":  result.elapsed(),
            "summary":  summary,
            "findings": [f.to_dict() for f in result.sorted_findings()],
        })
        _emit(scan_id, "target_done",
              target=target, summary=summary, elapsed=result.elapsed())

    with _lock:
        scans[scan_id]["status"]   = "done"
        scans[scan_id]["finished"] = datetime.now().isoformat()
        scans[scan_id]["results"]  = all_results

    _emit(scan_id, "all_done", total_targets=len(targets))
