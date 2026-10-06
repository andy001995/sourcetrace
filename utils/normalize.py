# utils/normalize.py
# URL 归一化：拼接相对路径、去掉锚点、域名小写、默认端口剔除、查询参数排序。
# 用途：保证「不重复」——同一接口因写法不同（大小写 / 参数顺序 / 相对路径）只会被识别一次。
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
