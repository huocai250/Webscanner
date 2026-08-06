"""
插件系统：从目录热加载自定义扫描模块
Author: 火柴 | GitHub: huocai250

在指定目录（默认 plugins/）中放置 .py 文件，其中定义任意继承自
BaseScanner 的类，即可被自动发现并纳入扫描计划。

插件类需满足：
  - 继承 core.scanner.BaseScanner
  - 定义类属性 name（唯一）与 passive（bool）
  - 实现 run(self)

参考 plugins/example_plugin.py。
"""
import os
import importlib.util
import inspect
from core.scanner import BaseScanner
from core.colors import log


def load_plugins(plugins_dir: str) -> list:
    """加载目录下所有插件，返回 BaseScanner 子类列表。"""
    classes = []
    if not plugins_dir or not os.path.isdir(plugins_dir):
        return classes

    for fname in sorted(os.listdir(plugins_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(plugins_dir, fname)
        modname = f"wvs_plugin_{fname[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as e:
            log("WARN", f"插件加载失败 {fname}: {e}")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BaseScanner) and obj is not BaseScanner
                    and obj.__module__ == module.__name__):
                classes.append(obj)
                log("INFO", f"已加载插件模块: {getattr(obj, 'name', obj.__name__)} ({fname})")
    return classes
