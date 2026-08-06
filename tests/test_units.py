"""
纯函数单元测试（无需网络）
运行:  cd webscanner && python -m pytest tests/ -v
       或  python tests/test_units.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import (extract_forms, extract_links, url_params,
                        strip_query, build_url, parse_cookies)
from core.config import ScanConfig
from core.result import ScanResult


# ---------------- utils.http ----------------
def test_parse_cookies():
    assert parse_cookies("a=1; b=2") == {"a": "1", "b": "2"}
    assert parse_cookies("") == {}
    assert parse_cookies("x=y=z") == {"x": "y=z"}


def test_url_params():
    assert url_params("http://h/p?a=1&b=2") == {"a": "1", "b": "2"}
    assert url_params("http://h/p") == {}
    assert url_params("http://h/p?flag=") == {"flag": ""}


def test_strip_and_build():
    assert strip_query("http://h/p?a=1") == "http://h/p"
    out = build_url("http://h/p?a=1", {"a": "2", "b": "3"})
    assert url_params(out) == {"a": "2", "b": "3"}
    assert out.startswith("http://h/p?")


def test_extract_links_same_host_only():
    html = ('<a href="/a">x</a><a href="http://other.com/b">y</a>'
            '<a href="http://h/c">z</a><a href="javascript:void(0)">j</a>')
    links = extract_links(html, "http://h/")
    assert "http://h/a" in links
    assert "http://h/c" in links
    assert all("other.com" not in l for l in links)
    assert all("javascript" not in l for l in links)


def test_extract_forms():
    html = ('<form method="post" action="/login">'
            '<input name="user" value="admin"><input name="pw"></form>')
    forms = extract_forms(html, "http://h/")
    assert len(forms) == 1
    assert forms[0]["method"] == "POST"
    assert forms[0]["action"] == "http://h/login"
    assert "user" in forms[0]["inputs"] and "pw" in forms[0]["inputs"]


# ---------------- core.config (scope) ----------------
def test_scope_default_locks_host():
    c = ScanConfig(target="http://app.example.com")
    assert c.in_scope("http://app.example.com/x")
    assert not c.in_scope("http://api.example.com/x")   # 子域默认不在范围
    assert not c.in_scope("http://evil.com")


def test_scope_suffix_match():
    c = ScanConfig(target="http://app.example.com", scope=["example.com"])
    assert c.in_scope("http://api.example.com")
    assert c.in_scope("http://example.com")
    assert not c.in_scope("http://evilexample.com")     # 不能被后缀误匹配
    assert not c.in_scope("http://evil.com")


def test_normalized_target():
    assert ScanConfig(target="example.com").normalized_target() == "http://example.com"
    assert ScanConfig(target="https://x").normalized_target() == "https://x"


# ---------------- core.result (dedup + scoring) ----------------
def test_result_dedup():
    r = ScanResult("t")
    assert r.add("XSS", "HIGH", "same", url="u") is True
    assert r.add("XSS", "HIGH", "same", url="u") is False   # 重复被忽略
    assert len(r.findings) == 1


def test_risk_score_and_grade():
    r = ScanResult("t")
    assert r.risk_score() == 0 and r.risk_grade() == "良好"
    r.add("SQL 注入", "CRITICAL", "x")
    r.add("XSS", "HIGH", "y")
    assert r.risk_score() == 60
    assert r.risk_grade() == "高危"
    # 评分封顶 100
    for i in range(5):
        r.add("SQL 注入", "CRITICAL", f"c{i}")
    assert r.risk_score() == 100
    assert r.risk_grade() == "严重"


def test_summary_counts():
    r = ScanResult("t")
    r.add("a", "HIGH", "1"); r.add("b", "HIGH", "2"); r.add("c", "LOW", "3")
    s = r.summary()
    assert s["HIGH"] == 2 and s["LOW"] == 1 and s["CRITICAL"] == 0


# ---------------- v8: 作用域 ----------------
def test_in_scope_locks_host():
    cfg = ScanConfig(target="http://example.com")
    assert cfg.in_scope("http://example.com/a") is True
    # 默认锁定目标主机（含其子域），但不允许其它主机
    assert cfg.in_scope("http://evil.com") is False
    assert cfg.in_scope("http://example.com.evil.com") is False
    assert cfg.in_scope("http://sub.example.com") is True


def test_in_scope_suffix():
    cfg = ScanConfig(target="http://example.com", scope=["example.com"])
    assert cfg.in_scope("http://sub.example.com") is True
    assert cfg.in_scope("http://example.com") is True
    assert cfg.in_scope("http://notexample.com") is False


# ---------------- v8: 配置文件 ----------------
def test_configfile_parsing(tmp_path=None):
    import tempfile
    from core.configfile import load_config_file
    content = ("[scanner]\nthreads = 20\ntimeout = 5\npassive = true\n"
               "canary = my.oob.test\nskip = subdomain, ports\n")
    p = tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False, encoding="utf-8")
    p.write(content); p.close()
    cfg = load_config_file(p.name)
    assert cfg["threads"] == 20
    assert cfg["timeout"] == 5.0
    assert cfg["passive"] is True
    assert cfg["canary"] == "my.oob.test"
    assert cfg["skip"] == {"subdomain", "ports"}


# ---------------- v8: JWT 解码 ----------------
def test_jwt_regex_and_decode():
    from modules.jwt_check import JWT_RE, _b64d
    import json
    tok = ("eyJhbGciOiJub25lIn0."
           "eyJ1c2VyIjoiYm9iIiwiaXNfYWRtaW4iOnRydWV9.")
    found = JWT_RE.findall("cookie=" + tok + "; other=1")
    assert tok in found
    header = json.loads(_b64d(tok.split(".")[0]))
    payload = json.loads(_b64d(tok.split(".")[1]))
    assert header["alg"] == "none"
    assert payload["is_admin"] is True


# ---------------- v8: 指纹版本提取 ----------------
def test_fingerprint_version():
    from modules.fingerprint import Fingerprinter
    hdrs = {"x-powered-by": "PHP/7.4.3", "server": "nginx/1.18.0"}
    # PHP 版本来自 x-powered-by，不应被 CMS generator 污染
    assert Fingerprinter._version_for("PHP", "语言", hdrs, "WordPress 5.8") == "7.4.3"
    assert Fingerprinter._version_for("Nginx", "服务器", hdrs, "") == "1.18.0"
    # CMS 才用 generator
    assert Fingerprinter._version_for("WordPress", "CMS", hdrs, "WordPress 5.8") == "5.8"


if __name__ == "__main__":
    # 允许不装 pytest 也能跑
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} 通过")
    sys.exit(0 if passed == len(fns) else 1)
