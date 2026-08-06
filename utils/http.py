"""
HTTP 工具函数
Author: 火柴 | GitHub: huocai250
v4.0: 增加 URL 参数解析/注入、更健壮的表单与链接提取
"""
import re
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse


def extract_forms(html: str, base_url: str = "") -> list[dict]:
    """提取页面中所有表单及其字段（含 action 归一化）。"""
    forms = []
    for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
        attrs_str, body = form_match.groups()
        method = re.search(r'method\s*=\s*["\']?(\w+)', attrs_str, re.I)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs_str, re.I)

        inputs = {}
        # input / textarea / select 的 name
        for m in re.finditer(
                r'<(?:input|textarea|select)[^>]*\bname\s*=\s*["\']([^"\']+)["\']([^>]*)',
                body, re.I):
            name = m.group(1)
            val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', m.group(2), re.I)
            inputs[name] = (val_m.group(1) if val_m else "") or "test"

        action_url = action.group(1) if action else ""
        if base_url and action_url:
            action_url = urljoin(base_url, action_url)
        elif base_url:
            action_url = base_url

        forms.append({
            "method": (method.group(1).upper() if method else "GET"),
            "action": action_url,
            "inputs": inputs,
        })
    return forms


def extract_links(html: str, base_url: str) -> list[str]:
    """提取页面中所有同源链接（href/src）。"""
    refs = re.findall(r'(?:href|src)\s*=\s*["\']([^"\'#]+)["\']', html, re.I)
    base_host = urlparse(base_url).netloc
    links = set()
    for h in refs:
        h = h.strip()
        if h.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        full = urljoin(base_url, h)
        if urlparse(full).netloc == base_host:
            links.add(full.split("#")[0])
    return list(links)


def extract_params(html: str) -> dict:
    """从页面提取输入参数名。"""
    names = re.findall(r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']', html, re.I)
    return {n: "test" for n in names}


def url_params(url: str) -> dict:
    """解析 URL 查询串为 dict。"""
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


def strip_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def build_url(base: str, params: dict) -> str:
    """将参数编码回 URL（覆盖原有查询串）。"""
    p = urlparse(base)
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       urlencode(params, doseq=True), ""))


def parse_cookies(cookie_str: str) -> dict:
    """解析 Cookie 字符串。"""
    cookies = {}
    for part in (cookie_str or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies
