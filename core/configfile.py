"""
配置文件加载（scanner.cfg）
Author: 火柴 | GitHub: huocai250

用 INI 格式集中管理默认参数，命令行参数优先级高于配置文件。
示例见项目根目录 scanner.cfg.example。
"""
import configparser

# 配置键 -> (类型, ScanConfig 字段名)
_MAP = {
    "timeout": (float, "timeout"),
    "threads": (int, "threads"),
    "retries": (int, "retries"),
    "delay": (float, "delay"),
    "jitter": (float, "jitter"),
    "rate": (float, "rate"),
    "max_urls": (int, "max_urls"),
    "max_depth": (int, "max_depth"),
    "verify_ssl": (bool, "verify_ssl"),
    "random_agent": (bool, "random_agent"),
    "passive": (bool, "passive"),
    "proxy": (str, "proxy"),
    "user_agent": (str, "user_agent"),
    "canary": (str, "canary"),
    "wordlist": (str, "wordlist_file"),
    "subdomain_wordlist": (str, "subdomain_wordlist"),
    "plugins_dir": (str, "plugins_dir"),
}


def load_config_file(path: str) -> dict:
    """读取 INI 配置，返回可用于覆盖 ScanConfig 的字典。"""
    parser = configparser.ConfigParser()
    read = parser.read(path, encoding="utf-8")
    if not read:
        raise FileNotFoundError(f"无法读取配置文件: {path}")

    out = {}
    # 支持 [scanner] 段或 DEFAULT 段
    section = parser["scanner"] if parser.has_section("scanner") else parser["DEFAULT"]
    for key, (typ, field) in _MAP.items():
        if key not in section:
            continue
        raw = section[key].strip()
        if raw == "":
            continue
        if typ is bool:
            out[field] = raw.lower() in ("1", "true", "yes", "on")
        elif typ is int:
            out[field] = int(raw)
        elif typ is float:
            out[field] = float(raw)
        else:
            out[field] = raw

    # skip 模块列表（逗号分隔）
    if "skip" in section and section["skip"].strip():
        out["skip"] = {s.strip().lower() for s in section["skip"].split(",")}

    return out
