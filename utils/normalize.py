# utils/normalize.py
# URL 归一化：拼接相对路径、去掉锚点、域名小写、默认端口剔除、查询参数排序。
# 用途：保证「不重复」——同一接口因写法不同（大小写 / 参数顺序 / 相对路径）只会被识别一次。
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


def normalize_url(base_url: str, resource_url: str) -> str:
    """将 resource_url 相对 base_url 归一化；非 http(s) 协议（data: 等）原样返回。"""
    if not resource_url:
        return ""
    if resource_url.startswith(("data:", "javascript:", "blob:", "chrome-extension:", "moz-extension:")):
        return resource_url
    full = urljoin(base_url, resource_url)
    parts = urlparse(full)
    scheme = parts.scheme.lower()
    host = parts.netloc.lower()
    # 去掉默认端口
    if host.endswith(":80") and scheme == "http":
        host = host[:-3]
    elif host.endswith(":443") and scheme == "https":
        host = host[:-4]
    path = parts.path or "/"
    # 查询参数排序后重新拼接，保证不同顺序视为同一资源
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunparse((scheme, host, path, "", query, ""))  # 丢弃 fragment


def same_origin(a: str, b: str) -> bool:
    """判断两个 URL 是否同源（协议 + 主机完全一致）。"""
    pa, pb = urlparse(a), urlparse(b)
    return pa.scheme.lower() == pb.scheme.lower() and pa.netloc.lower() == pb.netloc.lower()


def is_http_url(url: str) -> bool:
    """仅 http/https 视为可调用的业务接口；ws/wss/data 等另作他论。"""
    return urlparse(url).scheme.lower() in ("http", "https", "")


# ==================== 静态资源 / 第三方库判定（采集、解析、链路映射共用） ====================
# 静态资源扩展名（以这些结尾的路径不是业务 API）
STATIC_ASSET_EXTS = (
    ".js", ".mjs", ".cjs", ".css", ".less", ".scss", ".json", ".xml", ".txt",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".mp3", ".pdf",
    ".html", ".htm",
)
# 静态资源目录标记（路径段命中其一即视为静态目录）
_STATIC_DIR_SEGS = {
    "tpl", "template", "templates", "static", "assets", "dist", "public",
    "vendor", "node_modules", "js", "css", "_js2", "js2", "lib", "libs",
    "scripts", "script", "upload", "_upload", "uploads",
}
# 第三方库文件名特征（命中即视为 vendor，不做业务 AST 解析，避免压缩库触发 tree-sitter 崩溃）
_VENDOR_NAME_PATTERNS = (
    "jquery", "vue", "react", "angular", "bootstrap", "lodash", "underscore",
    "moment", "element-ui", "elementui", "antd", "echarts", "chart", "highcharts",
    "prototype", "scriptaculous", "ext-all", "modernizr", "select2", "swiper",
    "slick", "layui", "layer", "ueditor", "ckeditor", "tinymce", "kindeditor",
    "wangeditor", "html5shiv", "respond", "popper", "three", "font-awesome",
    "fontawesome", "animate", "core-js", "babel", "runtime", "polyfill",
    "promise", "loadstyle", "isie", "browser", "common.js", "public.js",
)


def _path(url: str) -> str:
    return urlparse(url).path.lower()


def is_minified(url: str) -> bool:
    """.min.js / .min.css 等压缩产物（用户要求直接排除）。"""
    p = _path(url)
    return re.search(r"[-.]min\.(js|mjs|cjs|css)$", p) is not None


def is_static_asset(url: str) -> bool:
    """判断 URL 是否为静态资源（非业务 API）。

    严格按用户规则（AND，不扩大）：
      1) 以静态资源扩展名结尾（.js/.mjs/.cjs/.css/图片/字体等）→ 静态资源；
         业务 API（如 /api/admin/template/render、/product/list）不以静态扩展名结尾，不会被误判；
      2) 「位于 /tpl/ /template/ /static/ /assets/ 等目录」必须「且以 .js/.css 等静态扩展名结尾」
         才判静态资源——该 AND 条件已被规则 1 覆盖，故绝不仅凭目录段判定
         （否则 /api/admin/template/render 会因含 "template" 段被误杀）。
    """
    p = _path(url)
    if p.endswith(STATIC_ASSET_EXTS):
        return True
    return False


def is_vendor_asset(url: str, content: str | None = None) -> bool:
    """判断 URL 是否为第三方/公共库资源。"""
    p = _path(url)

    if is_minified(url):
        return True

    segs = [s for s in p.split("/") if s]
    if any(s in ("vendor", "node_modules") for s in segs):
        return True

    base = p.split("/")[-1]
    if not any(v in base for v in _VENDOR_NAME_PATTERNS):
        return False

    if content is None:
        return True

    for pat in (
        r'\$\.(ajax|post|get|getJSON)\s*\(',
        r'\bfetch\s*\(',
        r'\baxios\.\w+\s*\(',
        r'\bXMLHttpRequest\b',
    ):
        if re.search(pat, content):
            return False

    return True



