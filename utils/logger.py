# utils/logger.py
# 日志工具：同时输出到控制台与 task.log，统一时间格式。
import logging
import sys

from config import BASE_DIR

_FORMATTER = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(_FORMATTER)

_file = logging.FileHandler(BASE_DIR / "task.log", encoding="utf-8")
_file.setFormatter(_FORMATTER)

logger = logging.getLogger("sourcetrace")
logger.setLevel(logging.INFO)
logger.addHandler(_console)
logger.addHandler(_file)
logger.propagate = False
