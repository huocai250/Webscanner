"""
PoC 验证引擎（nuclei 兼容子集）v12.0
Author: 火柴 | GitHub: huocai250

在 v11 的「请求 + 匹配」模板引擎之上，扩展为可执行自动化 PoC 验证的引擎：
  - 兼容 nuclei `http:` 模板语法（method/path/raw/headers/body/matchers/extractors）
  - 支持多请求串联、变量/helper（{{BaseURL}}、{{randstr}}、{{base64()}} 等）
  - 支持 extractor 提取变量并在后续请求中引用（internal）
  - 支持 payloads 模糊测试（batteringram / pitchfork / clusterbomb）
  - 支持 DSL 匹配器（contains/len/regex/to_lower 等安全求值，不执行任意代码）
  - 支持 req-condition、stop-at-first-match、cookie 复用、redirects 控制
  - OOB 探测：{{interactsh-url}} 映射到 --canary 指定域名（需自建 collaborator 观测）

安全边界：PoC 模板只做「漏洞验证」，默认载荷为无害标记/回显类；本引擎不执行
模板中的任何代码（DSL 仅做白名单式求值）。请仅对已获书面授权的目标使用。
"""
import base64
import hashlib
import json
import os
import random
import re
import string
import time
from urllib.parse import quote, unquote, urlparse

SEV_MAP = {
    "info": "INFO", "low": "LOW", "medium": "MEDIUM",
    "high": "HIGH", "critical": "CRITICAL",
}

# ---------------- 动态 helper ----------------


def _randstr(n=8):
    try:
        n = int(n)
    except (TypeError, ValueError):
        n = 8
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(max(1, n)))


def _randint(a=0, b=9999):
    try:
        return random.randint(int(a), int(b))
    except (TypeError, ValueError):
        return random.randint(0, 9999)


def _b64(s):
    return base64.b64encode(str(s).encode()).decode()


def _b64d(s):
    try:
        return base64.b64decode(str(s)).decode(errors="ignore")
    except Exception:
        return ""


def _urlenc(s):
    return quote(str(s), safe="")


def _urlenc_all(s):
    return quote(str(s), safe="")


def _urldec(s):
    return unquote(str(s))


def _md5(s):
    return hashlib.md5(str(s).encode()).hexdigest()


def _sha1(s):
    return hashlib.sha1(str(s).encode()).hexdigest()


def _sha256(s):
    return hashlib.sha256(str(s).encode()).hexdigest()


def _hexdec(s):
    try:
        return bytes.fromhex(str(s)).decode(errors="ignore")
    except Exception:
        return str(s)


def _hexenc(s):
    return str(s).encode().hex()


def _tolower(s):
    return str(s).lower()


def _toupper(s):
    return str(s).upper()


def _trim(s):
    return str(s).strip()


HELPERS = {
    "randstr": _randstr, "rand_int": _randint, "randint": _randint,
    "base64": _b64, "base64_decode": _b64d, "url_encode": _urlenc,
    "url_decode": _urldec, "md5": _md5, "sha1": _sha1, "sha256": _sha256,
    "hex_decode": _hexdec, "hex_encode": _hexenc, "to_lower": _tolower,
    "to_upper": _toupper, "trim": _trim,
}

# {{name}} / {{name(args)}} 两种形态
_HELPER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*\}\}")


def _resolve_helpers(text, variables):
    """把字符串中的 {{var}} / {{func(args)}} 全部替换。"""
    if not isinstance(text, str) or "{{" not in text:
        return text

    def repl(m):
        name, args = m.group(1), (m.group(2) or "").strip()
        if name in variables:
            val = variables[name]
            return str(val) if val is not None else ""
        fn = HELPERS.get(name)
        if fn is not None:
            # 参数支持嵌套 {{}}，先解析一层
            if args:
                parsed = [a.strip().strip("'\"") for a in _split_args(args)]
                try:
                    return str(fn(*parsed))
                except Exception:
                    return ""
            try:
                return str(fn())
            except Exception:
                return ""
        return m.group(0)

    for _ in range(3):          # 多轮展开，处理嵌套
        if "{{" not in text:
            break
        new = _HELPER_RE.sub(repl, text)
        if new == text:
            break
        text = new
    return text


def _split_args(args):
    """按逗号切分函数参数（忽略括号内逗号，支持字符串引号）。"""
    parts, cur, depth, quote_ch = [], "", 0, None
    for ch in args:
        if quote_ch:
            cur += ch
            if ch == quote_ch:
                quote_ch = None
            continue
        if ch in ("'", '"'):
            quote_ch, cur = ch, cur + ch
        elif ch == "(":
            depth, cur = depth + 1, cur + ch
        elif ch == ")":
            depth, cur = depth - 1, cur + ch
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


# ---------------- DSL 匹配器（白名单求值） ----------------

_TOKEN_RE = re.compile(
    r"\s*(?:(?P<num>\d+(?:\.\d+)?)|(?P<str>'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")|"
    r"(?P<op>==|!=|<=|>=|=~|!~|&&|\|\||[<>()!,])|(?P<ident>[A-Za-z_][A-Za-z0-9_.]*))\s*",
    re.S,
)


class _DSLError(Exception):
    pass


def _tokenize(expr):
    toks, pos = [], 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise _DSLError(f"无法解析: {expr[pos:pos+40]!r}")
        if m.group("num"):
            toks.append(("num", float(m.group("num"))))
        elif m.group("str"):
            s = m.group("str")[1:-1].replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
            toks.append(("str", s))
        elif m.group("op"):
            toks.append(("op", m.group("op")))
        elif m.group("ident"):
            toks.append(("ident", m.group("ident")))
        pos = m.end()
    toks.append(("eof", ""))
    return toks


class _DSL:
    """递归下降求值器：只支持白名单函数与字段，杜绝任意代码执行。"""

    FUNCS = {
        "contains": lambda a, b: str(b) in str(a),
        "contains_all": lambda a, b: all(str(x) in str(a) for x in _as_list(b)),
        "contains_any": lambda a, b: any(str(x) in str(a) for x in _as_list(b)),
        "starts_with": lambda a, b: str(a).startswith(str(b)),
        "ends_with": lambda a, b: str(a).endswith(str(b)),
        "len": lambda a: len(a),
        "regex": lambda a, b: bool(re.search(str(b), str(a))),
        "to_lower": _tolower,
        "to_upper": _toupper,
        "to_string": lambda a: str(a),
        "int": lambda a: int(float(a)),
        "concat": lambda *a: "".join(str(x) for x in a),
        "join": lambda a, sep=",": str(sep).join(str(x) for x in _as_list(a)),
        "trim": _trim,
        "substr": lambda a, s, e=None: str(a)[int(s):(int(e) if e is not None else None)],
        "replace": lambda a, o, n: str(a).replace(str(o), str(n)),
        "split": lambda a, sep: str(a).split(str(sep)),
        "hex_decode": _hexdec,
        "base64_decode": _b64d,
    }

    def __init__(self, fields):
        self.fields = fields

    def eval(self, expr):
        self.toks = _tokenize(expr)
        self.pos = 0
        v = self._or()
        if self._peek()[0] != "eof":
            raise _DSLError(f"多余 token: {self._peek()}")
        return v

    def _peek(self):
        return self.toks[self.pos]

    def _next(self):
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def _or(self):
        v = self._and()
        while self._peek()[0] == "op" and self._peek()[1] in ("||", "or"):
            self._next()
            r = self._and()
            v = bool(v) or bool(r)
        return v

    def _and(self):
        v = self._cmp()
        while self._peek()[0] == "op" and self._peek()[1] in ("&&", "and"):
            self._next()
            r = self._cmp()
            v = bool(v) and bool(r)
        return v

    def _cmp(self):
        v = self._unary()
        t = self._peek()
        if t[0] == "op" and t[1] in ("==", "!=", "<", "<=", ">", ">=", "=~", "!~"):
            self._next()
            r = self._unary()
            op = t[1]
            if op == "==":
                return v == r
            if op == "!=":
                return v != r
            if op == "<":
                return v < r
            if op == "<=":
                return v <= r
            if op == ">":
                return v > r
            if op == ">=":
                return v >= r
            if op == "=~":
                return bool(re.search(str(r), str(v)))
            if op == "!~":
                return not re.search(str(r), str(v))
        return v

    def _unary(self):
        t = self._peek()
        if t[0] == "op" and t[1] == "!":
            self._next()
            return not bool(self._unary())
        if t[0] == "ident" and t[1] == "not":
            self._next()
            return not bool(self._unary())
        return self._primary()

    def _primary(self):
        t = self._next()
        if t[0] == "num" or t[0] == "str":
            return t[1]
        if t[0] == "ident":
            name = t[1]
            if name in ("true", "True"):
                return True
            if name in ("false", "False"):
                return False
            if name in ("null", "nil", "None"):
                return None
            if self._peek()[0] == "op" and self._peek()[1] == "(":
                self._next()
                args = []
                if not (self._peek()[0] == "op" and self._peek()[1] == ")"):
                    while True:
                        args.append(self._or())
                        p = self._next()
                        if p[0] == "op" and p[1] == ")":
                            break
                        if not (p[0] == "op" and p[1] == ","):
                            raise _DSLError(f"期望逗号: {p}")
                fn = self.FUNCS.get(name)
                if fn is None:
                    raise _DSLError(f"未知函数: {name}")
                try:
                    return fn(*args)
                except Exception:
                    return None
            return self.fields.get(name)
        if t[0] == "op" and t[1] == "(":
            v = self._or()
            p = self._next()
            if not (p[0] == "op" and p[1] == ")"):
                raise _DSLError("缺少右括号")
            return v
        raise _DSLError(f"意外 token: {t}")


def _as_list(x):
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]


def dsl_match(expr, fields):
    """安全求值 DSL 表达式；失败返回 False（不中断扫描）。"""
    try:
        return bool(_DSL(fields).eval(expr))
    except Exception:
        return False


# ---------------- 加载 ----------------

def _load_yaml(path):
    try:
        import yaml
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = list(yaml.safe_load_all(f))
        docs = []
        for d in data:
            if isinstance(d, dict):
                docs.append(d)
            elif isinstance(d, list):
                docs += [x for x in d if isinstance(x, dict)]
        return docs
    except Exception:
        return []


def load_poc_dirs(dirs, index_file=None, use_index=True):
    """加载 PoC 模板。优先使用预构建 index.json（快速），再增量加载
    pocs/custom 与用户 --pocs 目录（YAML 实时解析）。"""
    templates = []
    seen = set()
    if use_index and index_file and os.path.isfile(index_file):
        try:
            with open(index_file, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data = data.get("templates", [])
            for tpl in data:
                if isinstance(tpl, dict) and tpl.get("id"):
                    tpl.setdefault("_source", "index")
                    templates.append(tpl)
                    seen.add(tpl["id"])
        except Exception:
            templates = []
            seen = set()
    for d in dirs or []:
        if not d or not os.path.isdir(d):
            continue
        files = []
        for ext in ("*.yaml", "*.yml"):
            files += glob_join(d, ext)
        for path in sorted(files):
            for tpl in _load_yaml(path):
                if not isinstance(tpl, dict) or not tpl.get("id"):
                    continue
                if tpl["id"] in seen:
                    continue
                tpl["_source"] = os.path.relpath(path, d) if os.path.isabs(path) else path
                templates.append(tpl)
                seen.add(tpl["id"])
    return templates


def glob_join(d, ext):
    import glob
    return glob.glob(os.path.join(d, "**", ext), recursive=True)


def poc_stats(templates):
    """统计模板库：总数 / 各严重级 / 可运行 HTTP 模板数。"""
    total = len(templates)
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    runnable = 0
    for t in templates:
        s = str((t.get("info") or {}).get("severity", "info")).lower()
        sev[s] = sev.get(s, 0) + 1
        reqs = t.get("http") or t.get("requests") or []
        if any(isinstance(r, dict) and (r.get("method") or r.get("path") or r.get("paths") or r.get("raw")) for r in reqs):
            runnable += 1
    return {"total": total, "runnable": runnable, "severity": sev}


# ---------------- PoC 运行器 ----------------

class PocRunner:
    """对单个目标执行 PoC 模板。"""

    MAX_PAYLOAD_COMBOS = 500   # 单模板模糊测试组合上限，防止组合爆炸

    def __init__(self, scanner, templates, canary=None):
        self.s = scanner
        self.templates = templates
        self.canary = canary

    # ---- 基础变量 ----
    def _base_vars(self, tpl, req_index=0):
        target = self.s.target.rstrip("/")
        p = urlparse(target)
        root = f"{p.scheme}://{p.netloc}"
        host = p.hostname or ""
        port = p.port
        host_header = p.netloc if not (port and ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443))) else f"{host}:{port}"
        token = _randstr(6)
        canary = self.canary or "oob.canary.example"
        vars_ = {
            "baseURL": target,
            "BaseURL": target,
            "root_url": root,
            "RootURL": root,
            "Hostname": host_header,
            "hostname": host,
            "Host": host_header,
            "path": p.path or "/",
            "interactsh-url": f"{token}.{canary}",
            "interactsh_protocol": "http",
            "randstr": _randstr(),
            "rand_int": _randint(),
        }
        # 模板级 variables
        tv = tpl.get("variables") or {}
        if isinstance(tv, list):
            for item in tv:
                if isinstance(item, dict):
                    for k, v in item.items():
                        vars_[k] = _resolve_helpers(str(v), vars_)
        elif isinstance(tv, dict):
            for k, v in tv.items():
                vars_[k] = _resolve_helpers(str(v), vars_)
        # 请求级 variables
        return vars_

    def _vars_with(self, tpl, req, base, payload=None, extracted=None):
        vars_ = dict(base)
        if extracted:
            vars_.update(extracted)
        rv = req.get("variables") or {}
        if isinstance(rv, list):
            for item in rv:
                if isinstance(item, dict):
                    for k, v in item.items():
                        vars_[k] = _resolve_helpers(str(v), vars_)
        elif isinstance(rv, dict):
            for k, v in rv.items():
                vars_[k] = _resolve_helpers(str(v), vars_)
        if payload:
            vars_.update(payload)
            vars_["payload"] = next(iter(payload.values()), "")
        return vars_

    # ---- 请求构造 ----
    def _build_request(self, req, vars_):
        method = str(req.get("method", "GET")).upper()
        headers = dict(req.get("headers") or {})
        body = req.get("body")
        raw_path = req.get("paths") or req.get("path") or [""]
        if isinstance(raw_path, str):
            raw_path = [raw_path]
        paths = raw_path
        raw = req.get("raw")

        if raw:
            raws = raw if isinstance(raw, list) else [raw]
            out = []
            for r0 in raws:
                if isinstance(r0, str) and r0.strip():
                    out += self._from_raw(_resolve_helpers(r0, vars_), vars_)
            return out

        out = []
        for p in paths:
            p = _resolve_helpers(str(p or ""), vars_)
            if p.startswith(("http://", "https://")):
                url = p
            elif p.startswith("/"):
                url = self.s.url(p.lstrip("/"))
            else:
                url = self.s.url(p)
            hdrs = {_resolve_helpers(str(k), vars_): _resolve_helpers(str(v), vars_)
                    for k, v in headers.items()}
            b = _resolve_helpers(body, vars_) if isinstance(body, str) else body
            out.append((method, url, hdrs, b))
        return out

    def _from_raw(self, raw_text, vars_):
        lines = raw_text.replace("\r\n", "\n").split("\n")
        first = lines[0].strip()
        parts = first.split()
        method = parts[0].upper() if parts else "GET"
        target = parts[1] if len(parts) > 1 else "/"
        headers, body_lines, in_body = {}, [], False
        for ln in lines[1:]:
            if in_body:
                body_lines.append(ln)
                continue
            if ln.strip() == "":
                in_body = True
                continue
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip()] = v.strip()
        body = "\n".join(body_lines)
        if target.startswith(("http://", "https://")):
            url = target
        elif target.startswith("/"):
            url = self.s.url(target.lstrip("/"))
        else:
            url = self.s.url(target)
        return [(method, url, headers, body)]

    # ---- 提取器 ----
    def _extract(self, req, resp, vars_):
        out = {}
        for ex in req.get("extractors") or []:
            if not isinstance(ex, dict):
                continue
            etype = ex.get("type")
            part = ex.get("part", "body")
            hay = self._part_text(resp, part)
            vals = []
            if etype == "regex":
                group = int(ex.get("group", 0))
                for pat in ex.get("regex") or []:
                    try:
                        m = re.search(pat, hay)
                        if m and m.lastindex is not None and group <= m.lastindex:
                            vals.append(m.group(group))
                        elif m:
                            vals.append(m.group(0))
                    except re.error:
                        pass
            elif etype == "word":
                for w in ex.get("words") or []:
                    if w in hay:
                        vals.append(w)
            elif etype == "kval":
                for k in ex.get("kval") or []:
                    v = resp.headers.get(k)
                    if v is not None:
                        vals.append(v)
            elif etype == "json":
                import json as _json
                try:
                    data = _json.loads(resp.text or "{}")
                    for path in ex.get("json") or []:
                        v = _json_get(data, path)
                        if v is not None:
                            vals.append(str(v))
                except Exception:
                    pass
            if not vals:
                continue
            name = ex.get("name") or ""
            if ex.get("internal") and name:
                out[name] = vals[0]
        return out

    def _part_text(self, resp, part):
        body = resp.text or ""
        header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        raw_resp = f"HTTP/1.1 {resp.status_code}\n{header_blob}\n\n{body}"
        part = (part or "body").lower()
        if part in ("header", "all_headers"):
            return header_blob
        if part == "raw" or part == "response":
            return raw_resp
        if part == "all":
            return header_blob + "\n" + body
        return body

    # ---- 匹配器 ----
    def _match(self, req, resp, state, req_index):
        matchers = req.get("matchers") or []
        if not matchers:
            return False
        cond = str(req.get("matchers-condition", "or")).lower()
        results = [self._match_one(m, resp, state, req_index) for m in matchers]
        return all(results) if cond == "and" else any(results)

    def _match_one(self, m, resp, state, req_index):
        mtype = m.get("type")
        neg = bool(m.get("negative", False))
        ci = bool(m.get("case-insensitive", False))
        part = m.get("part", "body")

        ok = False
        if mtype == "status":
            ok = resp.status_code in (m.get("status") or [])
        elif mtype == "size":
            cl = len(resp.content or b"")
            ok = cl in (m.get("size") or [])
        elif mtype == "word":
            hay = self._part_text(resp, part)
            words = m.get("words") or []
            c = str(m.get("condition", "or")).lower()
            if ci:
                hay = hay.lower()
                words = [w.lower() for w in words]
            checks = [w in hay for w in words]
            ok = all(checks) if c == "and" else any(checks)
        elif mtype == "regex":
            hay = self._part_text(resp, part)
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
        elif mtype == "dsl":
            exprs = m.get("dsl") or []
            c = str(m.get("condition", "or")).lower()
            checks = [dsl_match(e, self._dsl_fields(resp, state, req_index)) for e in exprs]
            ok = all(checks) if c == "and" else any(checks)
        return (not ok) if neg else ok

    def _dsl_fields(self, resp, state, req_index):
        body = resp.text or ""
        header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        raw_resp = f"HTTP/1.1 {resp.status_code}\n{header_blob}\n\n{body}"
        fields = {
            "status_code": resp.status_code,
            "body": body,
            "header": header_blob,
            "all_headers": header_blob,
            "content_length": len(resp.content or b""),
            "duration": 0,
            "response_time": 0,
            "raw": raw_resp,
            "response": raw_resp,
            "request": "",
        }
        fields.update(state.get("extracted") or {})
        fields.update(state.get("payload") or {})
        # req-condition: 提供 body_1/status_code_1 等历史字段
        for i, prev in enumerate(state.get("responses") or [], 1):
            pb = prev.text or ""
            ph = "\n".join(f"{k}: {v}" for k, v in prev.headers.items())
            fields[f"body_{i}"] = pb
            fields[f"header_{i}"] = ph
            fields[f"all_headers_{i}"] = ph
            fields[f"status_code_{i}"] = prev.status_code
            fields[f"content_length_{i}"] = len(prev.content or b"")
        return fields

    # ---- payload 组合 ----
    def _payload_combos(self, req):
        payloads = req.get("payloads") or {}
        if not isinstance(payloads, dict):
            return [None]
        cleaned = {}
        for k, v in payloads.items():
            if isinstance(v, str) and not v.startswith("{{"):
                # 可能是文件路径（wordlist），跳过无法读取的
                if os.path.isfile(v):
                    try:
                        with open(v, encoding="utf-8", errors="ignore") as f:
                            vals = [ln.strip() for ln in f if ln.strip()]
                    except OSError:
                        vals = []
                else:
                    vals = []
            elif isinstance(v, (list, tuple)):
                vals = [str(x) for x in v]
            else:
                vals = [str(v)]
            if vals:
                cleaned[k] = vals
        if not cleaned:
            return [None]
        attack = str(req.get("attack", "batteringram")).lower()
        names = list(cleaned.keys())
        if attack == "pitchfork":
            n = max(len(cleaned[k]) for k in names)
            n = min(n, self.MAX_PAYLOAD_COMBOS)
            combos = []
            for i in range(n):
                combos.append({k: cleaned[k][i % len(cleaned[k])] for k in names})
            return combos
        if attack == "clusterbomb":
            import itertools
            prod = itertools.product(*[cleaned[k] for k in names])
            combos = []
            for vals in prod:
                combos.append(dict(zip(names, vals)))
                if len(combos) >= self.MAX_PAYLOAD_COMBOS:
                    break
            return combos
        # batteringram：各变量独立迭代（每次只替换一个变量集合 -> 简化：同步推进）
        n = max(len(cleaned[k]) for k in names)
        n = min(n, self.MAX_PAYLOAD_COMBOS)
        return [{k: cleaned[k][i % len(cleaned[k])] for k in names} for i in range(n)]

    # ---- 单请求执行 ----
    def _do_request(self, req, vars_, state, req_index):
        requests_ = self._build_request(req, vars_)
        out = []
        for method, url, headers, body in requests_:
            r = None
            allow_redirects = bool(req.get("redirects", True))
            if method == "POST":
                r = self.s.post(url, data=body, headers=headers or None,
                                allow_redirects=allow_redirects)
            else:
                r = self.s.get(url, headers=headers or None,
                               allow_redirects=allow_redirects)
            if r is None:
                continue
            ex = self._extract(req, r, vars_)
            state["extracted"].update(ex)
            state["responses"].append(r)
            out.append((r, url))
        return out

    # ---- 模板执行 ----
    def run_template(self, tpl):
        """执行单个模板。返回命中列表 [dict]，未命中返回 []。"""
        info = tpl.get("info", {}) or {}
        tpl_id = tpl.get("id", "")
        sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), "INFO")
        name = info.get("name", tpl_id)
        category = info.get("category", "PoC验证")
        hits = []

        requests_ = tpl.get("http") or tpl.get("requests") or []
        if not requests_:
            return hits

        base = self._base_vars(tpl)
        state = {"extracted": {}, "responses": [], "payload": {}}
        cookie_snapshot = _snapshot_cookies(self.s.session)

        try:
            for req in requests_:
                if not isinstance(req, dict):
                    continue
                # cookie 复用控制：默认不跨请求复用，cookie:true 时保留
                if not req.get("cookie"):
                    _restore_cookies(self.s.session, cookie_snapshot)
                combos = self._payload_combos(req)
                for combo in combos:
                    vars_ = self._vars_with(tpl, req, base, payload=combo,
                                           extracted=state["extracted"])
                    state["payload"] = combo or {}
                    responses = self._do_request(req, vars_, state, len(state["responses"]))
                    for r, url in responses:
                        if self._match(req, r, state, len(state["responses"])):
                            evidence = f"{req.get('method', 'GET').upper()} {url} -> {r.status_code}"
                            hits.append({
                                "id": tpl_id,
                                "name": name,
                                "category": category,
                                "severity": sev,
                                "url": url,
                                "evidence": evidence,
                                "confidence": "确认" if sev in ("HIGH", "CRITICAL") else "疑似",
                            })
                            # 命中即停：避免同模板多路径/多请求重复报告
                            return hits
        finally:
            _restore_cookies(self.s.session, cookie_snapshot)
        return hits


def _snapshot_cookies(session):
    try:
        return {c.name: c.value for c in session.cookies}
    except Exception:
        return {}


def _restore_cookies(session, snap):
    try:
        session.cookies.clear()
        for k, v in snap.items():
            session.cookies.set(k, v)
    except Exception:
        pass


def _json_get(data, path):
    """极简 JSONPath：支持 a.b[0].c 这类点分+下标路径。"""
    cur = data
    for part in re.split(r"(?<!\\)\.", path):
        part = part.strip()
        m = re.match(r"^([^\[\]]+)\[(\d+)\]$", part)
        if m:
            key, idx = m.group(1), int(m.group(2))
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
            if isinstance(cur, list) and idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(part)
            elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            else:
                return None
    return cur
