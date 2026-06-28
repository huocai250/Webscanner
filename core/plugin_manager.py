"""
插件管理器 — WebVulnScanner v7.0
Author: 火柴 | GitHub: huocai250

[新增] 插件热加载系统
- 用户可在 plugins/ 目录放自定义模块
- 继承 BaseScanner 即可，无需修改主程序
- 支持运行时热重载
"""
import os
import sys
import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Type

log = logging.getLogger("webscan")


class PluginManager:
    """
    插件管理器：自动发现并加载 plugins/ 目录下的扫描模块
    
    插件格式示例（plugins/my_scanner.py）：
    
        from core.scanner import BaseScanner
        
        # 必须定义 PLUGIN_META
        PLUGIN_META = {
            "name":        "我的扫描器",
            "key":         "my_scan",      # 模块唯一标识
            "description": "自定义检测逻辑",
            "author":      "你的名字",
            "version":     "1.0",
        }
        
        class MyScanner(BaseScanner):
            def run(self):
                _before = self.result.total()
                # 你的检测逻辑
                self._log_module_done("我的扫描器", _before)
    """

    PLUGIN_CLASS_ATTR = "PLUGIN_META"   # 插件必须定义的元数据属性

    def __init__(self, plugins_dir: str = None):
        self.plugins_dir = plugins_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "plugins"
        )
        self._plugins: Dict[str, dict] = {}   # key → {meta, cls, module}
        Path(self.plugins_dir).mkdir(parents=True, exist_ok=True)
        # 写示例插件
        self._write_example_plugin()

    def discover(self) -> List[dict]:
        """
        扫描 plugins/ 目录，加载所有合法插件
        返回已加载插件列表
        """
        loaded = []
        plugin_path = Path(self.plugins_dir)

        for py_file in sorted(plugin_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                plugin = self._load_file(py_file)
                if plugin:
                    loaded.append(plugin)
                    log.info(f"[插件] 加载成功: {plugin['meta']['name']} "
                             f"v{plugin['meta'].get('version','?')} "
                             f"by {plugin['meta'].get('author','unknown')}")
            except Exception as e:
                log.warning(f"[插件] 加载失败 {py_file.name}: {e}")

        if loaded:
            log.info(f"[插件系统] 共加载 {len(loaded)} 个插件")
        else:
            log.info("[插件系统] plugins/ 目录下暂无插件")

        return loaded

    def reload(self) -> List[dict]:
        """热重载：清空缓存重新扫描"""
        self._plugins.clear()
        # 清除 sys.modules 中的插件缓存
        to_remove = [k for k in sys.modules if k.startswith("plugin_")]
        for k in to_remove:
            del sys.modules[k]
        log.info("[插件系统] 热重载中...")
        return self.discover()

    def get_all(self) -> List[dict]:
        """获取所有已加载插件"""
        return list(self._plugins.values())

    def get_scanner_classes(self) -> List[Type]:
        """获取所有插件的扫描器类"""
        return [p["cls"] for p in self._plugins.values()]

    # ── 内部方法 ─────────────────────────────────────────────

    def _load_file(self, path: Path) -> dict | None:
        module_name = f"plugin_{path.stem}"
        spec   = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)

        # 注入 plugins 目录到 sys.path（让插件能 import 项目模块）
        proj_root = str(Path(self.plugins_dir).parent)
        if proj_root not in sys.path:
            sys.path.insert(0, proj_root)

        spec.loader.exec_module(module)

        # 检查是否有 PLUGIN_META
        if not hasattr(module, self.PLUGIN_CLASS_ATTR):
            return None   # 不是合法插件，静默跳过

        meta = getattr(module, self.PLUGIN_CLASS_ATTR)
        if not isinstance(meta, dict) or "key" not in meta:
            raise ValueError("PLUGIN_META 必须是含 'key' 字段的 dict")

        # 找 Scanner 类（继承自 BaseScanner 的第一个类）
        scanner_cls = self._find_scanner_class(module)
        if not scanner_cls:
            raise ValueError("插件中未找到继承 BaseScanner 的类")

        entry = {"meta": meta, "cls": scanner_cls, "module": module, "path": str(path)}
        self._plugins[meta["key"]] = entry
        return entry

    def _find_scanner_class(self, module):
        """在模块里找第一个继承 BaseScanner 的类"""
        import inspect
        from core.scanner import BaseScanner
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseScanner) and obj is not BaseScanner:
                return obj
        return None

    def _write_example_plugin(self):
        """首次运行时写一个示例插件"""
        example = Path(self.plugins_dir) / "example_plugin.py"
        if example.exists():
            return
        example.write_text('''"""
示例插件 — WebVulnScanner v7.0
把这个文件复制为你自己的插件，修改检测逻辑即可

使用方法：
  python main.py https://target.com   # 自动加载 plugins/ 下所有插件
"""
from core.scanner import BaseScanner

# 必须定义 PLUGIN_META
PLUGIN_META = {
    "name":        "示例插件（X-Powered-By检测）",
    "key":         "example",
    "description": "检测响应头是否泄露框架信息",
    "author":      "火柴",
    "version":     "1.0",
}


class ExampleScanner(BaseScanner):
    """检测 X-Powered-By 响应头"""

    def run(self):
        _before = self.result.total()
        self._check_powered_by()
        self._log_module_done(PLUGIN_META["name"], _before)

    def _check_powered_by(self):
        r = self.get(self.target)
        if not r:
            return
        header = r.headers.get("X-Powered-By", "")
        if header:
            self.result.add(
                category = "插件/信息泄露",
                severity = "LOW",
                detail   = f"X-Powered-By 泄露: {header}",
                url      = self.target,
            )
''', encoding="utf-8")
