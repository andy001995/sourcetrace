# config.py
# 全局配置模块：路径、采集三道保护、LLM Provider 抽象、网页服务与限流参数。
# 所有配置均支持环境变量覆盖，便于 Docker / 网页版 / CLI 三种形态共用同一套核心引擎。
import os
import pathlib

# ============ 路径 ============
BASE_DIR = pathlib.Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"          # 报告输出目录
RAW_JS_DIR = OUTPUT_DIR / "raw_js"        # 原始 JS 备份目录
BIN_DIR = BASE_DIR / "bin"                # jsluice 多平台二进制目录

for _d in (OUTPUT_DIR, RAW_JS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ============ 阶段2：采集三道保护（铁律参数，不可放宽到越界） ============
# 1) 单文件最大 2MB，超过跳过并告警
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(2 * 1024 * 1024)))
# 2) 递归最大深度 10 层
MAX_RECURSIVE_DEPTH = int(os.getenv("MAX_RECURSIVE_DEPTH", "10"))
# 3) 最大资源总数 500 个
MAX_RESOURCE_COUNT = int(os.getenv("MAX_RESOURCE_COUNT", "500"))
# 默认只采集与目标同域的资源（严格零主动探测姿态）；显式开启才允许跨域静态 CDN
ALLOW_CROSS_ORIGIN_STATIC = os.getenv("ALLOW_CROSS_ORIGIN_STATIC", "0") == "1"

# 采集请求（仅下载公开静态 HTML/JS/CSS 本身使用）
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))
USER_AGENT = os.getenv(
    "USER_AGENT",
    "Mozilla/5.0 (compatible; gvl-recon/1.0; passive static-resource analysis; "
    "only downloads public HTML/JS/CSS)",
)

# ============ 阶段3b：LLM 语义分析（可选增强，默认关闭，可插拔） ============
# 设计原则：LLM 语义分析是【可选功能】，不是核心功能。核心链路（采集/AST/去重/密钥识别）
#           在完全不配置 LLM 时也能完整运行；只有显式配置后才启用，未配置时绝不发起任何 LLM 请求。
#
# provider 取值: auto | openai | ollama | mock | off
#   auto（默认）-> 可插拔自动模式：
#                  · 配置了 LLM_API_KEY  -> 自动按 OpenAI 兼容协议启用（无需再改 provider）
#                  · 未配置 LLM_API_KEY  -> 自动关闭(off)，仅用 AST/正则 + 关键词规则
#   openai       -> 强制走 OpenAI 兼容 API（DeepSeek/通义/智谱/Kimi 等任何 OpenAI 协议服务）；
#                   但若未配置 LLM_API_KEY，会安全降级为 off（不发包）
#   ollama       -> 本地 Ollama 模型（需自行在本机运行 ollama serve，离线可用）
#   mock         -> 内置启发式规则（离线演示/测试，不发任何网络请求）
#   off          -> 显式关闭 LLM 语义分析
#
# 启用方式（二选一）：
#   A. 环境变量：  export LLM_PROVIDER=openai
#                 export LLM_API_KEY=sk-xxxx
#                 export LLM_BASE_URL=https://api.deepseek.com/v1   # 任意 OpenAI 兼容端点
#                 export LLM_MODEL=deepseek-chat
#   B. 直接改本文件下方默认值。
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").lower()
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# tree-sitter（C 扩展）单文件解析超时（秒）：tree-sitter 在独立子进程内解析，
# 超过该时长即 kill 子进程并降级 esprima。正常解析为毫秒~1 秒，30 秒对低性能 CPU 留足余量。
TS_FILE_TIMEOUT = float(os.getenv("TS_FILE_TIMEOUT", "30"))

# ============ 网页版服务 ============
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8000"))
SQLITE_DB_PATH = BASE_DIR / "task.db"     # 授权记录 + 任务状态 + 限流计数
# 免费/付费次数限制：每 IP 每日最多任务数（付费扩容只需调大该值）
MAX_TASKS_PER_IP_DAY = int(os.getenv("MAX_TASKS_PER_IP_DAY", "5"))
WEB_TOKEN = os.getenv("WEB_TOKEN", "")    # 可选访问令牌；留空表示不启用鉴权
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"  # 信任 X-Forwarded-For 取真实客户端 IP
