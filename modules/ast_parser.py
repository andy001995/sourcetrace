# modules/ast_parser.py
# 阶段3a：AST 源码解析
#
# 双保险策略（不漏）：
#   1) AST 解析：优先 acorn-python（用户点名的纯 Python 实现，若已安装则自动加载），
#      不可用时自动降级 esprima（PyPI 上稳定可用的纯 Python JS 解析器），
#      再不可用则仅依赖正则（兜底，置信度标"低"）。
#   2) 正则兜底：扫描 fetch / axios / $.ajax / XHR.open / 封装函数等模式。
#
# 过滤噪音 + 自动去重（不重复）。每条接口记录：
#   url、method、params（参数名）、source_file（文件:行号）、confidence（高/低）、extract_type
import json
import multiprocessing
import platform
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from config import BIN_DIR, TS_FILE_TIMEOUT
from utils.dedup import dedup_interfaces
from utils.logger import logger
from utils.normalize import is_http_url, is_static_asset, is_vendor_asset

# ==================== 解析器加载（按优先级） ====================
try:  # 1) acorn-python（用户点名的默认实现，若环境中已安装）
    from acorn_python import parse as _acorn_parse  # type: ignore
    _PARSER_NAME = "acorn-python"
except ImportError:  # 2) acorn（部分第三方绑定的导入名）
    try:
        from acorn import parse as _acorn_parse  # type: ignore
        _PARSER_NAME = "acorn"
    except ImportError:
        _acorn_parse = None
        _PARSER_NAME = None

try:  # 3) esprima：纯 Python 稳定兜底
    import esprima
    _HAVE_ESPRIMA = True
except ImportError:
    _HAVE_ESPRIMA = False

# 4) tree-sitter（错误容忍解析器，可选增强）：能解析现代/压缩 JS（可选链、顶层 await、
#    大对象字面量等 esprima 盲区），语法错误不影响整树提取。pip install tree-sitter tree-sitter-javascript
try:
    from tree_sitter import Language as _TSLanguage, Parser as _TSParser
    import tree_sitter_javascript as _TSJS
    _TS_LANG = _TSLanguage(_TSJS.language())
    _HAVE_TS = True
except Exception:
    _TS_LANG = None
    _HAVE_TS = False


# ==================== tree-sitter 子进程 worker（模块级，spawn 可调用） ====================
def _ts_worker(code: str, source_url: str, wrapper_index: dict, child_conn) -> None:
    """在【独立子进程】内运行 tree-sitter 解析（C 扩展）。

    隔离意义：tree-sitter 是 C 扩展，解析特定畸形 JS 时可能触发 Segmentation fault，
    进程被内核直接杀死，Python 的 try/except 无法捕获。把解析放进子进程后：
      · 子进程崩溃（如 SIGSEGV）只杀死子进程，主进程据 exitcode 判定并降级，其他文件照常解析；
      · 成功时通过 Pipe 把该文件提取出的接口记录列表（纯 dict，可序列化）回传主进程。
    注意：本函数必须是模块级函数，以便 spawn 子进程重新 import 后能找到目标。
    """
    try:
        # 子进程内使用全新解析器实例（不共享主进程任何状态）
        worker_parser = ASTApiParser({}, resource_refs=[])
        worker_parser.wrapper_index = wrapper_index
        tree = _TSParser(_TS_LANG).parse(bytes(code, "utf-8"))
        worker_parser._ts_walk(tree.root_node, code, source_url)
        child_conn.send(worker_parser.interfaces)
    except Exception as exc:  # 仅捕获 Python 层异常；C 层 segfault 由主进程据 exitcode 处理
        try:
            child_conn.send({"__ts_error__": "%s: %s" % (type(exc).__name__, str(exc)[:200])})
        except Exception:
            pass
    finally:
        try:
            child_conn.close()
        except Exception:
            pass

# ==================== 噪音过滤规则 ====================
# 统计/埋点等第三方遥测域名（命中即过滤）
_NOISE_HOSTS = (
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "hotjar.com", "sentry.io", "umeng.com", "cnzz.com", "hm.baidu.com",
    "polyfill.io", "facebook.net", "connect.facebook.net",
)
# 静态资源扩展名（非业务接口）
_STATIC_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".webp", ".avif", ".mp4", ".mp3", ".pdf",
)

# 正则兜底模式（置信度：低）
_REGEX_PATTERNS = (
    # fetch('url')
    (r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", "GET", None),
    # axios.get/post/put/patch/delete/head('url')
    (r"(?:axios|http|https|request)\.(get|post|put|patch|delete|head)\s*\(\s*['\"]([^'\"]+)['\"]", None, None),
    # $.get/$.post/$.ajax('url') 与 jQuery 别名
    (r"\$\s*\.\s*(?:ajax|get|post|put|delete)\s*\(\s*['\"]([^'\"]+)['\"]", None, None),
    (r"\$\s*\.\s*(?:ajax|get|post|put|delete)\s*\(\s*\{[^}]{0,500}?url\s*:\s*['\"]([^'\"]+)['\"]", None, None),
    # XHR: xhr.open('POST', '/url')
    (r"\.open\s*\(\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD)['\"]\s*,\s*['\"]([^'\"]+)['\"]", None, None),
    # 模板字符串中的接口路径 /api/xxx/${id}
    (r"fetch\s*\(\s*`([^`]+)`", "GET", None),
    # axios/http/request 直接调用（无 .method 链）：$axios("/path") / axios("/path")
    (r"(?:\$?axios|\$?http|\$?request)\s*\(\s*['\"](/[^'\"]{3,})['\"]", "GET", None),
    # 配置对象里的接口常量：{CART_LIST: "/orders/web/cart/v1/list"}
    (r"\b[A-Z][A-Z0-9_]{2,}\s*:\s*['\"](/[a-zA-Z0-9_/.-]{4,})['\"]", "GET", None),
)
# baseURL / API_HOST 等配置常量（用于上下文，不作为独立接口）
_BASEURL_RE = re.compile(r"baseURL\s*[:=]\s*['\"]([^'\"]+)['\"]", re.M)
# API 域名常量（app.js 里的 INTERNAL_API 等）
_BASEURL_ALT_RE = re.compile(
    r"\b(?:INTERNAL_API|API_BASE|API_URL|API_HOST|BASE_URL)\s*[:=]\s*['\"]([^'\"]+)['\"]",
    re.M | re.I)
# WebSocket 端点（业务信道，仅记录提示，不请求）
_WS_RE = re.compile(r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]")

# ==================== 硬编码敏感密钥检测 ====================
# 形如 const JWT_SECRET = 'lab-secret' / window.TOKEN = "xxx"
_SECRET_KEY_RE = re.compile(
    r"(?:const|let|var|window\.|export\s+default\s*)?\s*"
    r"(?P<name>JWT_SECRET|SECRET_KEY|API_KEY|ACCESS_TOKEN|PRIVATE_KEY|"
    r"SESSION_SECRET|SECRET|PASSWORD|PASS|TOKEN)"
    r"\s*[:=]\s*['\"](?P<value>[^'\"]{3,})['\"]",
    re.M | re.I,
)
# 对象属性形式硬编码凭据（如 TEST_ACCOUNT = { user:'alice', pass:'alice123' }）
_SECRET_OBJ_RE = re.compile(
    r"\b(?P<name>PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY)\b\s*:\s*['\"](?P<value>[^'\"]{3,})['\"]",
    re.M | re.I,
)
# 占位值/示例值：命中的不视为真实密钥
_SECRET_PLACEHOLDERS = {
    "your_secret", "your_secret_key", "your-api-key", "change_me", "changeme",
    "example", "demo", "secret", "password", "passw0rd", "placeholder",
    "xxx", "xxxx", "****", "null", "undefined", "none",
}

# ==================== 封装函数链路（本地封装 HTTP 调用） ====================
# 形态：function n(i,t){ ... await m.post(i,t,...) ... }，调用点 n("/api/...",{...})
# 预扫描函数声明（最多看函数体前 3000 字符，防止大文件跨函数误配）
_WRAPPER_DECL_RE = re.compile(
    r"function\s+(?P<fn>\w+)\s*\((?P<params>[^)]*)\)\s*\{(?P<body>[\s\S]{0,3000}?)(?=\bfunction\b|\Z)",
    re.M,
)
# 函数体内 .verb(param, 的调用形态
_VERB_PARAM_RE = re.compile(r"\.(get|post|put|patch|delete|head)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]")
# 调用点：n("/url"[, {...}])  —— 第一个参数为字符串字面量
_WRAPPER_CALL_RE = re.compile(
    r"\b(?P<fn>\w+)\s*\(\s*['\"](?P<url>[^'\"]+)['\"]\s*(?:,\s*(?P<obj>\{[^{}]*\}))?\s*\)"
)
# WebSocket 端点（业务信道，仅记录提示，不请求）
_WS_RE = re.compile(r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]")


def _jsluice_binary() -> str | None:
    """按平台命名规则在 bin/ 目录探测 jsluice 二进制；系统 PATH 中的 jsluice 也可用。"""
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    sysname = platform.system().lower()
    if sysname.startswith("windows"):
        candidates = [f"jsluice-windows-{arch}.exe", "jsluice.exe"]
    elif sysname.startswith("darwin"):
        candidates = [f"jsluice-darwin-{arch}", "jsluice"]
    else:
        candidates = [f"jsluice-linux-{arch}", "jsluice"]
    for name in candidates:
        candidate = BIN_DIR / name
        if candidate.exists() and candidate.stat().st_size > 0:
            return str(candidate)
    return shutil.which("jsluice")


# 通用 member 调用兜底：u.get("/ai/...")、m.post("/api/...") 等 import 别名封装。
# AST 解析失败时的保底（配合 AST 形态2 去重合并）。
_GENERIC_VERB_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|head)\s*\(\s*['\"](/[^'\"]+)['\"]"
    r"\s*(?:,\s*(?:\w+\s*:\s*)?(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}|\w+))?",
    re.M,
)


def _sanitize_js(code: str) -> str:
    """轻量语法容错预处理（仅解析层使用，不改变接口提取语义）：
    压缩产物常用的可选链 a?.b、空值合并 a ?? b 是旧版 esprima 的解析盲区，
    替换为等价结构后 AST 引擎即可恢复命中。误伤字符串的概率极低。"""
    code = re.sub(r"(\w|\]|\)|\})\?\.", r"\1.", code)
    code = re.sub(r"(\w|\]|\)|\})\?\?", r"\1||", code)
    return code


def _is_noise(item: dict) -> bool:
    """过滤噪音：非 http(s)、遥测域名、静态资源（含 .js/.min.js/模板目录）、空路径、无路径标识。"""
    url = item.get("url", "")
    parsed = urlparse(url)
    if not is_http_url(url):
        return True
    host = parsed.netloc.lower()
    if any(h in host for h in _NOISE_HOSTS):
        return True
    # 静态资源一律不是业务 API：以静态扩展名结尾（.js/.css/.min.js 等）或位于静态/模板目录
    if is_static_asset(url):
        return True
    if parsed.path in ("", "/"):
        return True
    # 相对路径但完全不含斜杠（如误把标识符 'length' 当接口）——非业务接口
    if parsed.scheme == "" and "/" not in parsed.path:
        return True
    return False


class ASTApiParser:
    """从 JS 源码字典中提取业务接口清单。"""

    def __init__(self, js_store: dict[str, str], resource_refs: list[dict] | None = None):
        self.js_store = js_store
        # HTML 引用的静态资源清单（来自 collector，用于生成 /config.js 等资源条目）
        self.resource_refs = resource_refs or []
        self.interfaces: list[dict] = []
        self.base_urls: list[str] = []   # baseURL 配置（上下文信息）
        self.ws_endpoints: list[str] = []  # WebSocket 端点（提示信息）
        # 硬编码敏感密钥（如 JWT_SECRET='lab-secret'）
        self.secrets: list[dict] = []
        # 封装函数索引：{函数名: {参数名: [HTTP动词,...]}}（预扫描得到）
        self.wrapper_index: dict[str, dict[str, list[str]]] = {}
        # 缺失 chunk（本地模式由 collector 记录，这里汇总日志）
        self.missing_chunks: list[str] = []
        # tree-sitter 子进程崩溃/超时/异常的文件（含原因），用于报告如实披露
        self.crashed_files: list[dict] = []

    # ==================== 入口 ====================
    def run(self) -> list[dict]:
        """执行 AST + 正则提取，返回去重后的接口清单。"""
        if not self.js_store:
            logger.warning("无 JS 源码可解析（采集可能为空）")
            return []

        parser_note = "AST(tree-sitter)" if _HAVE_TS else (
            "AST(%s)" % _PARSER_NAME if _PARSER_NAME else "AST(esprima)")
        jsluice_bin = _jsluice_binary()
        if jsluice_bin:
            logger.info("检测到 jsluice 增强解析器: %s", jsluice_bin)

        # 预扫描封装函数（function n(i,t){ m.post(i,...) }），供 AST 形态4 识别
        self._build_wrapper_index()
        if self.wrapper_index:
            logger.info("识别到封装函数 %d 个: %s", len(self.wrapper_index),
                        ", ".join(list(self.wrapper_index)[:10]))

        vendor_skipped = []
        for url, code in self.js_store.items():
            # 第三方/公共库（jquery.min.js 等）不做业务解析：
            #   1) 压缩库与业务接口无关；2) 压缩大文件易触发 tree-sitter 崩溃。
            # 仅在采集层已备份，这里整体跳过，避免假接口与崩溃。
            if is_vendor_asset(url, content=code):
                vendor_skipped.append(url)
                continue
            self._extract_base_urls(code)
            self._extract_ws(code, url)
            # 0) 硬编码敏感密钥扫描（如 JWT_SECRET='lab-secret'）
            self._extract_secrets(code, url)
            # 1) AST 解析（高置信）
            self._ast_extract(code, url)
            # 2) 正则兜底（低置信，防 AST 解析失败漏项）
            self._regex_extract(code, url)
            # 3) 可选增强：jsluice 多平台二进制（bin/ 目录自动探测，用户无感）
            if jsluice_bin:
                self._jsluice_extract(code, url, jsluice_bin)

        # 注：HTML 引用的静态资源（<script src>/<link href>）不再混入 interfaces，
        # 由报告层单独整理写入 static_assets.json（严格区分静态资源与业务 API）。
        if vendor_skipped:
            logger.info("跳过第三方/公共库 %d 个（不做业务解析）: %s",
                        len(vendor_skipped), ", ".join(vendor_skipped[:8]))

        raw_count = len(self.interfaces)
        self.interfaces = [i for i in self.interfaces if not _is_noise(i)]
        self.interfaces = dedup_interfaces(self.interfaces)
        # 密钥去重
        seen_keys = set()
        uniq_secrets = []
        for s in self.secrets:
            key = (s.get("name"), s.get("value"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            uniq_secrets.append(s)
        self.secrets = uniq_secrets
        if not self.interfaces:
            # 传统 jQuery 网站等场景：没有现代 API 调用时如实返回空，不拿静态资源凑数
            logger.info("接口提取完成：未在前端 JS 中发现 API 调用（静态资源已单独归类，不凑数）")
        else:
            high_cnt = sum(1 for i in self.interfaces if i.get("confidence") == "高")
            low_cnt = sum(1 for i in self.interfaces if i.get("confidence") in ("低", "中"))
            logger.info(
                "接口提取完成：原始 %d 条，过滤噪音后 %d 条（解析器: %s，高置信 %d / 低置信 %d），"
                "硬编码密钥 %d 条",
                raw_count,
                len(self.interfaces),
                parser_note,
                high_cnt,
                low_cnt,
                len(self.secrets),
            )
        return self.interfaces

    # ==================== 封装函数索引（预扫描全部源码） ====================
    def _build_wrapper_index(self) -> None:
        """扫描所有 JS：识别 function 内部调用 HTTP 动词并将首个参数透传的「封装函数」。
        结果写入 self.wrapper_index，供 AST 形态4 与正则兜底共同使用。"""
        if self.wrapper_index:
            return
        for _url, code in self.js_store.items():
            for decl in _WRAPPER_DECL_RE.finditer(code):
                fn = decl.group("fn")
                params = [p.strip() for p in decl.group("params").split(",") if p.strip()]
                body = decl.group("body")
                mapping: dict[str, list[str]] = {}
                for verb_match in _VERB_PARAM_RE.finditer(body):
                    verb, pname = verb_match.group(1).lower(), verb_match.group(2)
                    if pname in params:
                        mapping.setdefault(pname, []).append(verb)
                if mapping:
                    self.wrapper_index.setdefault(fn, {}).update(mapping)

    # ==================== 硬编码敏感密钥 ====================
    def _extract_secrets(self, code: str, source_url: str) -> None:
        """扫描 const/let/var/window.XXX = '值' 与对象属性 {pass:'xxx'} 形式的硬编码凭据。
        占位/示例值（demo/your_secret 等）自动剔除，避免噪音。"""
        for m in _SECRET_KEY_RE.finditer(code):
            name, value = m.group("name"), m.group("value")
            if value.lower() in _SECRET_PLACEHOLDERS:
                continue
            line = code.count("\n", 0, m.start()) + 1
            self.secrets.append({
                "name": name, "value": value,
                "source_file": f"{source_url}:{line}",
                "kind": "key",
            })
        for m in _SECRET_OBJ_RE.finditer(code):
            name, value = m.group("name"), m.group("value")
            if value.lower() in _SECRET_PLACEHOLDERS:
                continue
            line = code.count("\n", 0, m.start()) + 1
            self.secrets.append({
                "name": name, "value": value,
                "source_file": f"{source_url}:{line}",
                "kind": "object_key",
            })

    # ==================== 上下文信息 ====================
    def _extract_base_urls(self, code: str) -> None:
        for match in _BASEURL_RE.finditer(code):
            val = match.group(1).strip()
            if val and val not in self.base_urls:
                self.base_urls.append(val)
        # API 域名常量（INTERNAL_API = 'http://api.example.com/api/internal/'）
        for match in _BASEURL_ALT_RE.finditer(code):
            val = match.group(1).strip()
            if val and val not in self.base_urls:
                self.base_urls.append(val)

    def _extract_ws(self, code: str, source_url: str) -> None:
        for match in _WS_RE.finditer(code):
            self.ws_endpoints.append(f"{match.group(1)} (见 {source_url})")

    # ==================== AST 解析 ====================
    def _parse(self, code: str):
        """按优先级调用 AST 解析器；全部失败抛异常由调用方捕获。"""
        if _acorn_parse is not None:
            try:
                return _acorn_parse(code, {"locations": True})
            except TypeError:
                return _acorn_parse(code)
            except Exception:
                pass
        if _HAVE_ESPRIMA:
            try:
                return esprima.parseScript(code, {"loc": True})
            except Exception:
                return esprima.parseModule(code, {"loc": True})
        raise RuntimeError("no AST parser available")

    def _ast_extract(self, code: str, source_url: str) -> None:
        # 0) tree-sitter：在【独立子进程】内错误容忍解析（最高优先级，覆盖 esprima 盲区）
        if _HAVE_TS:
            if self._ts_in_subprocess(code, source_url):
                return  # tree-sitter 子进程正常处理（含"无调用"的空结果）
            # 子进程崩溃/超时/异常：已记录 crashed_files，继续降级 esprima（纯 Python，不会 segfault）
            logger.warning("tree-sitter 不可用于 %s，降级 esprima", source_url)
        self._esprima_extract(code, source_url)

    # ==================== tree-sitter 子进程隔离（崩溃/超时保护） ====================
    def _ts_in_subprocess(self, code: str, source_url: str) -> bool:
        """用 spawn 子进程解析单个文件，返回 True=正常处理，False=崩溃/超时/异常（需降级）。

        保护机制：
          · spawn 上下文：完全独立进程，不继承父进程 C 扩展状态；
          · join(timeout)：超时则 kill 子进程，标记 timeout；
          · exitcode 判定：0=正常；负值=被信号杀死（SIGSEGV=-11 等）；
          · 子进程回传的接口记录直接并入主进程 self.interfaces（跨文件去重在 run() 统一做）。
        """
        try:
            ctx = multiprocessing.get_context("spawn")
            parent_conn, child_conn = ctx.Pipe(duplex=False)
            proc = ctx.Process(
                target=_ts_worker,
                args=(code, source_url, self.wrapper_index, child_conn),
            )
            proc.start()
            proc.join(TS_FILE_TIMEOUT)
        except Exception as exc:
            self._record_crash(source_url, "无法启动 tree-sitter 子进程：%s" % exc)
            return False

        # 正常退出：读取子进程回传数据
        if proc.exitcode == 0:
            data = None
            try:
                if parent_conn.poll(2):
                    data = parent_conn.recv()
            except Exception as exc:
                self._record_crash(source_url, "读取子进程结果异常：%s" % exc)
                return False
            if isinstance(data, list):
                for rec in data:           # 子进程已完成 _emit，记录为纯 dict
                    self.interfaces.append(rec)
                return True
            if isinstance(data, dict) and "__ts_error__" in data:
                self._record_crash(source_url, "tree-sitter Python 异常：%s" % data["__ts_error__"])
                return False
            # exitcode=0 但无数据：文件中确实没有可提取调用（正常，非崩溃），不降级
            return True

        # 异常退出：超时（exitcode None）或被信号杀死（负值）
        if proc.exitcode is None:
            proc.kill()
            proc.join(5)
            self._record_crash(
                source_url,
                "tree-sitter 解析超时（>%.0fs），子进程已 kill" % TS_FILE_TIMEOUT,
            )
        else:
            signame = self._signal_name(proc.exitcode)
            self._record_crash(
                source_url,
                "tree-sitter 子进程崩溃（exitcode=%s%s），主进程未受影响"
                % (proc.exitcode, signame),
            )
        return False

    def _record_crash(self, source_url: str, reason: str) -> None:
        """记录导致 tree-sitter 子进程崩溃/超时/异常的文件及原因（写日志 + 供报告披露）。"""
        self.crashed_files.append({"file": source_url, "reason": reason})
        logger.warning("⚠ [隔离] %s：%s", source_url, reason)

    @staticmethod
    def _signal_name(exitcode: int) -> str:
        """把负的信号退出码转成信号名（如 -11 -> SIGSEGV），便于报告定位。"""
        try:
            return "，信号=%s" % signal.Signals(-exitcode).name
        except Exception:
            return ""

    # ==================== esprima（纯 Python 降级解析） ====================
    def _esprima_extract(self, code: str, source_url: str) -> None:
        """tree-sitter 不可用时的纯 Python AST 解析（含整体解析 + 分块降级）。"""
        if _acorn_parse is None and not _HAVE_ESPRIMA:
            logger.debug("AST 解析器不可用，仅走正则: %s", source_url)
            return
        # 压缩产物可选链/空值合并语法容错（仅解析层）
        code = _sanitize_js(code)
        try:
            ast = self._parse(code)
        except Exception as exc:
            logger.debug("AST 整体解析失败 %s，降级为分块解析: %s", source_url, str(exc)[:60])
            self._ast_extract_chunks(code, source_url)
            return
        self._walk(ast, source_url)

    # ==================== tree-sitter 遍历（错误容忍 AST） ====================
    def _ts_walk(self, node, code: str, source_url: str) -> None:
        """深度优先遍历 tree-sitter 树；每个 call_expression 转为 esprima 风格 dict
        后复用 _handle_call（fetch / member 动词 / 封装函数 / axios 单对象等形态全覆盖）。

        迭代实现（显式栈），避免深嵌套压缩 JS 触发递归栈溢出。
        说明：tree-sitter 0.26.0 对部分大文件即使迭代遍历也会 SIGSEGV，
        故 requirements 已 pin 到 0.23.2；显式栈是额外的深嵌套防御。"""
        MAX_NODES = 5_000_000
        visited = 0
        stack = [node]
        while stack:
            cur = stack.pop()
            visited += 1
            if visited > MAX_NODES:
                self.warnings.append(
                    f"tree-sitter 遍历节点数超限（>{MAX_NODES}），提前停止: {source_url}"
                )
                return
            if cur.type == "call_expression":
                try:
                    call = self._ts_call_to_dict(cur, code)
                    if call.get("callee"):
                        self._handle_call(call, source_url)
                except Exception:
                    pass
            # 显式栈遍历（避免递归栈溢出与 TreeCursor 缺陷）
            stack.extend(cur.children)

    @staticmethod
    def _ts_text(node, code: str) -> str:
        return code[node.start_byte:node.end_byte]

    def _ts_expr_to_dict(self, node, code: str) -> dict:
        """tree-sitter 表达式节点 -> 统一 AST dict（供 _string_from_arg/_object_keys 消费）。"""
        t = node.type
        if t == "string":
            text = self._ts_text(node, code)
            if len(text) >= 2 and text[0] in "'\"`" and text[-1] == text[0]:
                text = text[1:-1]
            return {"type": "Literal", "value": text}
        if t == "template_string":
            text = self._ts_text(node, code)
            if len(text) >= 2 and text[0] == "`" and text[-1] == "`":
                text = text[1:-1]
            return {"type": "Literal", "value": text}  # 含 ${}，_emit 统一转为 {param}
        if t == "object":
            return self._ts_object_to_dict(node, code)
        if t == "identifier":
            return {"type": "Identifier", "name": self._ts_text(node, code)}
        if t in ("number", "true", "false", "null"):
            return {"type": "Literal", "value": self._ts_text(node, code)}
        # 其余类型（调用/成员/运算等）作为无价值占位，避免误当字符串
        return {"type": "Identifier", "name": ""}

    def _ts_object_to_dict(self, node, code: str) -> dict:
        props = []
        for child in node.named_children:
            if child.type == "pair":
                key = child.child_by_field_name("key")
                value = child.child_by_field_name("value")
                key_name = self._ts_text(key, code).strip('"\'') if key is not None else ""
                props.append({
                    "key": {"type": "Identifier", "name": key_name},
                    "value": self._ts_expr_to_dict(value, code) if value is not None
                             else {"type": "Identifier", "name": ""},
                })
        return {"type": "ObjectExpression", "properties": props}

    def _ts_call_to_dict(self, node, code: str) -> dict:
        """call_expression -> {type, callee, arguments, loc}（esprima 风格子集）。"""
        callee = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        callee_dict: dict | None = None
        if callee is not None:
            if callee.type == "member_expression":
                obj = callee.child_by_field_name("object")
                prop = callee.child_by_field_name("property")
                obj_dict = None
                if obj is not None and obj.type in ("identifier", "this", "super"):
                    obj_dict = {"type": "Identifier", "name": self._ts_text(obj, code)}
                prop_name = self._ts_text(prop, code) if prop is not None else ""
                callee_dict = {
                    "type": "MemberExpression",
                    "object": obj_dict or {"type": "Identifier", "name": ""},
                    "property": {"type": "Identifier", "name": prop_name},
                }
            elif callee.type == "identifier":
                callee_dict = {"type": "Identifier", "name": self._ts_text(callee, code)}
        args = []
        if args_node is not None:
            args = [self._ts_expr_to_dict(a, code) for a in args_node.named_children]
        return {
            "type": "CallExpression",
            "callee": callee_dict or {},
            "arguments": args,
            "loc": {"start": {"line": node.start_point.row + 1}},
        }

    def _ast_extract_chunks(self, code: str, source_url: str) -> None:
        """分块解析降级：整体解析失败时，按顶层分号把代码安全切成独立语句块，
        逐块尝试解析，坏块（esprima 不支持的现代语法）跳过、好块照常 AST 提取。
        保证真实压缩产物（Vue3/可选链/无参 catch 等）下 AST 引擎不整体失效。"""
        chunks = self._split_safe(code)
        ok_blocks = 0
        for seg in chunks:
            try:
                ast = self._parse(seg)
            except Exception:
                continue
            ok_blocks += 1
            self._walk(ast, source_url)
        if ok_blocks:
            logger.info("分块解析 %s：%d/%d 块成功", source_url, ok_blocks, len(chunks))

    def _split_safe(self, code: str) -> list[str]:
        """按顶层分号切分语句块：感知单/双引号、模板字符串、注释与括号深度，
        避免在字符串中间误切；跳过 for(;;) 等括号内分号。"""
        segs: list[str] = []
        start = 0
        depth = 0
        in_s: str | None = None   # 当前字符串定界符（'/"/`）
        esc = False
        i, n = 0, len(code)
        while i < n:
            ch = code[i]
            if in_s:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_s:
                    in_s = None
                i += 1
                continue
            if ch in ("'", '"', "`"):
                in_s = ch
                i += 1
                continue
            if ch == "/" and i + 1 < n and code[i + 1] in ("/", "*"):
                if code[i + 1] == "/":
                    j = code.find("\n", i)
                    i = n if j == -1 else j + 1
                else:
                    j = code.find("*/", i)
                    i = n if j == -1 else j + 2
                continue
            if ch in "({[":
                depth += 1
            elif ch in ")}]":
                depth = max(0, depth - 1)
            elif ch == ";" and depth == 0:
                nxt = i + 1
                while nxt < n and code[nxt] in " \t\r\n":
                    nxt += 1
                # 语句起点白名单：字母数字、下划线、$ 或左括号（注意：非字符区间）
                if nxt >= n or code[nxt].isalnum() or code[nxt] in "([{_$":
                    seg = code[start:i + 1].strip()
                    if len(seg) > 8:
                        segs.append(seg)
                    start = nxt
            i += 1
        tail = code[start:].strip()
        if len(tail) > 8:
            segs.append(tail)
        return segs[:200]  # 块数上限，防超大文件

    def _walk(self, node, source_url: str) -> None:
        """递归遍历 AST（兼容 dict 与 esprima 节点对象两种形态）。"""
        node = self._to_dict(node)
        if not isinstance(node, dict):
            return
        ntype = node.get("type")
        if ntype == "CallExpression":
            self._handle_call(node, source_url)
        for value in node.values():
            if isinstance(value, dict):
                self._walk(value, source_url)
            elif isinstance(value, list):
                for item in value:
                    self._walk(item, source_url)

    @staticmethod
    def _to_dict(node):
        if isinstance(node, dict):
            return node
        to_dict = getattr(node, "toDict", None)
        if callable(to_dict):
            return to_dict()
        return getattr(node, "__dict__", node)

    # ---------------- 调用识别 ----------------
    _VERBS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
              "delete": "DELETE", "head": "HEAD", "options": "OPTIONS"}

    def _handle_call(self, node: dict, source_url: str) -> None:
        callee = node.get("callee") or {}
        args = node.get("arguments") or []
        # 可选链包装（a?.b()）
        while callee.get("type") in ("ChainExpression", "OptionalCallExpression"):
            callee = callee.get("expression") or callee.get("callee") or {}
        ctype = callee.get("type", "")
        line = (node.get("loc") or {}).get("start", {}).get("line", 0)
        origin = f"{source_url}:{line}"

        # ---- 形态1: fetch('url'[, options]) ----
        if ctype == "Identifier" and callee.get("name") == "fetch" and args:
            url_val, hints = self._string_from_arg(args[0])
            if url_val:
                method = "GET"
                opts = args[1] if len(args) > 1 else None
                if opts is not None:
                    m = self._method_from_options(opts)
                    if m:
                        method = m
                    hints += self._body_keys_from_options(opts)
                self._emit(url_val, method, hints, origin, "高", "ast")
            return

        # ---- 形态2: axios.get / $.ajax / http.post / u.get / m.post 等 Member 调用 ----
        if ctype in ("MemberExpression", "OptionalMemberExpression"):
            obj = callee.get("object") or {}
            prop = callee.get("property") or {}
            obj_name = obj.get("name") if obj.get("type") == "Identifier" else None
            prop_name = prop.get("name") if prop.get("type") == "Identifier" else None
            # 放宽：对象为任意标识符（含 import 别名如 u/m/v/a）且属性为 HTTP 动词即命中。
            # 压缩产物里 axios 封装通常以 import 别名形式出现（import{a as m}from"./x.js"），
            # 固定对象名白名单会大量漏报；动词 + 字符串 URL 参数是足够强的接口信号。
            if prop_name and prop_name.lower() in self._VERBS and obj_name is not None:
                if args:
                    url_val, hints = self._string_from_arg(args[0])
                    if url_val:
                        body_hints = self._object_keys(args[1]) if len(args) > 1 else []
                        self._emit(url_val, self._VERBS[prop_name.lower()],
                                   hints + body_hints, origin, "高", "ast")
                return
            # $.ajax({url, method, data}) / axios({url, method}) 单对象参数
            if obj_name in ("$", "jQuery", "axios", "request") and prop_name in ("ajax", "request"):
                opts = args[0] if args else None
                url_val, hints = self._string_from_arg(self._prop_of(opts, "url")) if opts else (None, [])
                if url_val:
                    method = (self._literal_string(self._prop_of(opts, "method")) or "GET").upper()
                    data_node = self._prop_of(opts, "data")
                    body_hints = self._object_keys(data_node) if data_node else []
                    self._emit(url_val, method, hints + body_hints, origin, "高", "ast")
            return

        # ---- 形态3: axios('url', {method:'post'}) 直接调用 ----
        if ctype == "Identifier" and callee.get("name") in ("axios", "request", "http") and args:
            url_val, hints = self._string_from_arg(args[0])
            if url_val:
                method = "GET"
                if len(args) > 1:
                    m = self._method_from_options(args[1])
                    if m:
                        method = m
                    hints += self._body_keys_from_options(args[1])
                self._emit(url_val, method, hints, origin, "高", "ast")
            return

        # ---- 形态4: 封装函数调用 n("/api/...", {...}) ----
        # 函数内部形如 m.post(param1, ...)，URL 由调用点第一个字符串参数透传。
        # 预扫描结果见 self.wrapper_index：{函数名: {参数名: [动词,...]}}
        if ctype == "Identifier":
            fn_name = callee.get("name")
            mapping = self.wrapper_index.get(fn_name) if fn_name else None
            if mapping and args:
                url_val, hints = self._string_from_arg(args[0])
                if url_val:
                    # 用第一个能透传 URL 的参数对应的动词（通常就是第一个参数）
                    verbs = next(iter(mapping.values()), ["get"])
                    method = self._VERBS.get(verbs[0], "GET")
                    body_hints = self._object_keys(args[1]) if len(args) > 1 else []
                    self._emit(url_val, method, hints + body_hints, origin, "高", "ast_wrapper")

    # ---------------- 参数/URL 提取工具 ----------------
    def _string_from_arg(self, arg) -> tuple[str | None, list[str]]:
        """从 AST 节点提取字符串 URL。返回 (规范化 URL 模式, 参数名提示列表)。
        支持 Literal 与 TemplateLiteral（${expr} 转为 {param}）。"""
        if arg is None:
            return None, []
        node = self._to_dict(arg)
        ntype = node.get("type")
        if ntype == "Literal":
            val = node.get("value") or node.get("raw", "")
            if isinstance(val, str):
                return val, []
            return None, []
        if ntype == "TemplateLiteral":
            quasis = node.get("quasis") or []
            expressions = node.get("expressions") or []
            parts: list[str] = []
            hints: list[str] = []
            for idx, quasi in enumerate(quasis):
                parts.append((quasi.get("value") or {}).get("cooked", ""))
                if idx < len(expressions):
                    expr = self._to_dict(expressions[idx])
                    name = self._expr_hint(expr)
                    if name:
                        hints.append(name)
                    parts.append("{%s}" % name if name else "{param}")
            url = "".join(parts)
            return url, hints
        # 二元拼接：'path/' + id （AST 可识别，避免漏报；正则仅为兜底）
        if ntype == "BinaryExpression" and node.get("operator") == "+":
            left, right = node.get("left"), node.get("right")
            left_val, left_hints = self._string_from_arg(left) if left is not None else (None, [])
            if isinstance(left_val, str):
                hints = list(left_hints)
                right_dict = self._to_dict(right) if right is not None else {}
                if right_dict.get("type") == "Identifier" and right_dict.get("name"):
                    hints.append(right_dict["name"])
                return left_val, hints
        return None, []

    def _expr_hint(self, expr: dict) -> str:
        """从模板表达式推导参数名提示：标识符本身 / 成员表达式末段。"""
        etype = expr.get("type")
        if etype == "Identifier":
            return expr.get("name", "")
        if etype in ("MemberExpression", "OptionalMemberExpression"):
            prop = expr.get("property") or {}
            if prop.get("type") == "Identifier":
                return prop.get("name", "")
        return ""

    def _prop_of(self, node, key: str):
        """在 ObjectExpression 中查找指定属性节点。"""
        if node is None:
            return None
        node = self._to_dict(node)
        if node.get("type") != "ObjectExpression":
            return None
        for prop in node.get("properties") or []:
            prop = self._to_dict(prop)
            pkey = prop.get("key") or {}
            pkey_name = None
            if pkey.get("type") == "Identifier":
                pkey_name = pkey.get("name")
            elif pkey.get("type") == "Literal":
                pkey_name = pkey.get("value")
            if pkey_name == key:
                return prop.get("value")
        return None

    def _literal_string(self, node) -> str | None:
        node = self._to_dict(node) if node is not None else None
        if node and node.get("type") == "Literal":
            val = node.get("value")
            if isinstance(val, str):
                return val
        return None

    def _method_from_options(self, opts) -> str | None:
        m = self._literal_string(self._prop_of(opts, "method"))
        return m.upper() if m else None

    def _body_keys_from_options(self, opts) -> list[str]:
        """从 fetch 的 body / JSON 字符串中提取参数名提示（尽力而为）。"""
        if opts is None:
            return []
        body = self._prop_of(opts, "body")
        keys: list[str] = []
        if body is not None:
            body = self._to_dict(body)
            btype = body.get("type")
            if btype == "Literal":
                raw = body.get("value") or ""
                if isinstance(raw, str) and raw.lstrip().startswith("{"):
                    try:
                        obj = json.loads(raw)
                        keys = list(obj.keys())
                    except Exception:
                        # 形如 '{"a":1,"b":2}' 但非严格 JSON 时用正则粗提取
                        keys = re.findall(r'["\']([A-Za-z_][\w-]*)["\']\s*:', raw)
            elif btype == "Identifier":
                keys.append(body.get("name", ""))
        return keys

    def _object_keys(self, node) -> list[str]:
        """提取 ObjectExpression 的键名列表（用于请求体 data 参数提示）。
        支持两层嵌套（如 {params:{id:s}} -> ['params','id']）。"""
        node = self._to_dict(node) if node is not None else None
        if node is None or node.get("type") != "ObjectExpression":
            return []
        keys: list[str] = []

        def collect(obj_node, depth: int) -> None:
            obj_node = self._to_dict(obj_node) if obj_node is not None else None
            if obj_node is None or obj_node.get("type") != "ObjectExpression":
                return
            for prop in obj_node.get("properties") or []:
                prop = self._to_dict(prop)
                pkey = prop.get("key") or {}
                if pkey.get("type") == "Identifier":
                    key = pkey.get("name", "")
                elif pkey.get("type") == "Literal":
                    key = str(pkey.get("value", ""))
                else:
                    continue
                if key and key not in keys:
                    keys.append(key)
                if depth > 0:
                    collect(prop.get("value"), depth - 1)

        collect(node, 2)
        return keys

    # ---------------- 产出 ----------------
    def _emit(self, url: str, method: str, params: list[str],
              origin: str, confidence: str, extract_type: str) -> None:
        if not url or url.startswith(("data:", "javascript:", "blob:")):
            return
        if not is_http_url(url):
            return
        # 模板字符串模式统一化（/api/user/${id} -> /api/user/{id}）
        if "${" in url:
            url = re.sub(r"\$\{[^}]*\}", lambda m: "{%s}" % m.group(0)[2:-1].split(".")[-1] or "param", url)
        # 从 URL 查询串提取参数名提示（如 /api/x?a=1&b= -> params 含 a、b）
        parsed_q = urlparse(url)
        for key, _value in parse_qsl(parsed_q.query, keep_blank_values=True):
            if key and key not in params:
                params.append(key)
        self.interfaces.append({
            "url": url,
            "method": method,
            "params": list(dict.fromkeys(p for p in params if p)),
            "source_file": origin,
            "confidence": confidence,
            "extract_type": extract_type,
        })

    # ==================== jsluice 可选增强 ====================
    def _jsluice_extract(self, code: str, source_url: str, binary: str) -> None:
        """调用 jsluice 二进制提取 URL（--format json），结果并入接口清单（低置信）。
        二进制缺失/输出无法解析时静默跳过，不影响主流程。"""
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                             encoding="utf-8") as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            try:
                # jsluice 命令行兼容两种形态：`jsluice file.js --format json`
                # 与 `jsluice urls file.js --format json`
                for argv in (
                    [binary, tmp_path, "--format", "json"],
                    [binary, "urls", tmp_path, "--format", "json"],
                ):
                    try:
                        proc = subprocess.run(
                            argv, capture_output=True, timeout=30, text=True)
                        if proc.returncode == 0 and proc.stdout.strip():
                            self._absorb_jsluice_json(proc.stdout, source_url)
                            break
                    except (subprocess.TimeoutExpired, OSError):
                        continue
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        except Exception as exc:
            logger.debug("jsluice 增强解析跳过 %s: %s", source_url, exc)

    def _absorb_jsluice_json(self, raw: str, source_url: str) -> None:
        """宽容解析 jsluice JSON 输出：递归收集所有字符串，保留 http(s) 或 / 开头的路径。"""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        collected: list[str] = []

        def walk(obj):
            if isinstance(obj, dict):
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)
            elif isinstance(obj, str) and obj.strip():
                collected.append(obj.strip())

        walk(data)
        line = 0
        for value in collected:
            if value.startswith(("http://", "https://", "/")) and not value.startswith(("//", "/_")):
                self._emit(value, "GET", [], f"{source_url}:jsluice(line~{line})", "低", "jsluice")
            line += 1

    # ==================== 正则兜底 ====================
    def _regex_extract(self, code: str, source_url: str) -> None:
        # 剥离注释，避免误抓注释里的 URL（如废弃接口）
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
        # 注意：不再剥离 // 单行注释。
        # 压缩 JS 无换行，//[^\n]* 会从第一个 // 吞掉后续全部代码（实测 2aaff7f.js 的 51 处 $axios 全灭）。
        # /* */ 块注释保留剥离，它不受换行影响，误伤可控。

        # jQuery 变量拼接 URL 场景：url += "/_visitcountdisplay"
        if re.search(r'\$\.(ajax|post|get|getJSON)\s*\(', code):
            for m in re.finditer(
                r'\burl\s*\+?=\s*["\'](/[a-zA-Z0-9_?=&./%-]{3,})["\']',
                code
            ):
                path = m.group(1)
                line = code.count("\n", 0, m.start()) + 1
                self._emit(path, "GET", [], f"{source_url}:{line}", "低", "jquery_dynamic_url")
        # === 原始正则逻辑 ===

        for pattern, fixed_method, _ in _REGEX_PATTERNS:
            for match in re.finditer(pattern, code, re.M):
                groups = match.groups()
                if len(groups) == 1:
                    url = groups[0]
                    method = fixed_method or "GET"
                else:
                    url = groups[-1]
                    method = groups[0].upper() if groups[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD") else "GET"
                if not url:
                    continue
                if url.startswith(("'", '"', "`")):
                    url = url[1:]
                if url.endswith(("'", '"', "`")):
                    url = url[:-1]
                line = code.count("\n", 0, match.start()) + 1
                self._emit(url, method, [], f"{source_url}:{line}", "低", "regex")

        # 通用 member 调用兜底：u.get("/ai/...") / m.post("/api/...") / v.post(...)
        # （AST 形态2 已覆盖时自动去重合并；AST 失败时保证不漏）
        for match in _GENERIC_VERB_RE.finditer(code):
            _obj, verb, url = match.group(1), match.group(2), match.group(3)
            obj_str = match.group(4) or ""
            if not url:
                continue
            method = verb.upper()
            params = re.findall(r'["\']?(\w+)["\']?\s*:', obj_str) if obj_str else []
            line = code.count("\n", 0, match.start()) + 1
            self._emit(url, method, params, f"{source_url}:{line}", "低", "regex_member")

        # 封装函数调用兜底：n("/api/...",{...})（仅当 AST 形态4 未命中时补充，
        # 去重后与 AST 结果合并为一条）
        for match in _WRAPPER_CALL_RE.finditer(code):
            fn, url, obj_str = match.group("fn"), match.group("url"), match.group("obj")
            mapping = self.wrapper_index.get(fn)
            if not mapping or not url:
                continue
            verbs = next(iter(mapping.values()), ["get"])
            method = self._VERBS.get(verbs[0], "GET")
            # 对象字面量键名粗提取（防 AST 失败丢失参数提示）
            params = re.findall(r'["\']?(\w+)["\']?\s*:', obj_str) if obj_str else []
            line = code.count("\n", 0, match.start()) + 1
            self._emit(url, method, params, f"{source_url}:{line}", "低", "regex_wrapper")
