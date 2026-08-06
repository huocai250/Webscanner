import os
import sys

# 让 `python -m webscanner`（从上级目录运行）也能解析内部 top-level 导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import main  # noqa: E402

if __name__ == "__main__":
    main()
