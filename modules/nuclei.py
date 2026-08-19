"""
模板扫描模块（运行 YAML 签名库）
Author: 火柴 | GitHub: huocai250

加载内置 templates/ 目录（以及 --templates 指定的额外目录）中的模板并执行。
这是「1000+ 检测规则」可扩展的核心：新增检测只需新增 YAML 模板文件。
"""
import os
from core.scanner import BaseScanner
from core.colors import log
from core.template_engine import load_templates, TemplateRunner, count_checks

# 内置模板目录（包内 templates/）
BUILTIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "templates")


class TemplateScanner(BaseScanner):
    name = "templates"
    passive = True   # 模板均为「请求+匹配」式非侵入检测

    def run(self):
        dirs = [BUILTIN_DIR]
        extra = getattr(self.config, "templates_dir", None)
        if extra:
            dirs.append(extra)
        templates = load_templates(dirs)
        if not templates:
            log("INFO", "模板库为空，跳过模板扫描")
            return
        log("INFO", f"模板扫描：加载 {len(templates)} 个模板"
                    f"（{count_checks(templates)} 个检测点），并发执行...")
        runner = TemplateRunner(self, templates)
        hits = self.map(runner.run_template, templates)
        total = sum(len(h) for h in hits if h)
        if total:
            log("INFO", f"  模板命中 {total} 项")
        else:
            log("INFO", "  模板未命中")
