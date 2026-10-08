# modules/collector.py
# 阶段2：静态资源采集（双模式）
#
#   网络模式（默认）：只下载目标站点公开静态资源本身（HTML/JS/CSS/配置），
#     绝不向源码中提取出的业务 API 地址发送任何请求；默认仅同域。
#
#   本地目录模式（--local / target 为本地目录）：直接读取目录下所有文件，
#     零网络请求，便于离线测试与审计打包的源码。
#
# 边界铁律（代码级保证）：
#   - 无论哪种模式，都只接触「公开静态资源」本身；
#   - 提取出的 API 地址仅作为字符串记录，绝不对其发起任何请求。
#
# 三道保护（两种模式通用）：
#   1) 单文件最大 2MB（超过跳过并告警）
#   2) 递归最大深度 10 层
#   3) 最大资源总数 500 个
import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from config import (
    ALLOW_CROSS_ORIGIN_STATIC,
    MAX_FILE_SIZE,
    MAX_RECURSIVE_DEPTH,
    MAX_RESOURCE_COUNT,
    REQUEST_TIMEOUT,
    USER_AGENT,
)
from utils.logger import logger
from utils.normalize import normalize_url, same_origin

# 动态 chunk 发现正则：
#   1) import('./chunk.js')   —— 动态 import
#   2) import x from './m.js' —— ES module 静态导入
#   3) import './m.js'        —— 副作用导入
_IMPORT_LITERAL_RE = re.compile(r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.M)
_STATIC_IMPORT_RE = re.compile(r"import\s+[^'\"]*?\s+from\s*['\"]([^'\"]+)['\"]", re.M)
_SIDE_EFFECT_IMPORT_RE = re.compile(r"import\s*['\"]([^'\"]+)['\"]", re.M)

_JS_EXT = (".js", ".mjs", ".cjs")
_HTML_EXT = (".html", ".htm")


def _looks_like_js(text: str) -> bool:
    """启发式判断文本是否 JS 源码（用于无扩展名的 chunk）。"""
    head = text[:2000]
    return any(k in head for k in ("function ", "const ", "let ", "=>", "import ", "export "))


class ResourceCollector:
    """递归采集目标站点公开静态资源，输出 {url: JS源码文本} 字典。"""

    def __init__(self, target: str, raw_dir: str | Path | None = None,
                 local_mode: bool | None = None):
        self.target = target.rstrip("/")
        # 本地目录模式判定：显式指定，或 target 本身就是本地路径
        self.local_mode = local_mode if local_mode is not None else (
            os.path.isdir(target) or target.startswith(("./", "../")) or target == "."
        )
        # raw_js 备份目录（CLI 可用 --output 覆盖；不存在则自动创建）
        if raw_dir:
            self.raw_dir = Path(raw_dir)
            self.raw_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.raw_dir = None

        self.js_store: dict[str, str] = {}   # 虚拟URL/真实URL -> 源码
        self.visited: set[str] = set()       # 已访问（去重）
        self.resource_count = 0              # 资源总数计数（第3道保护）
        self.warnings: list[str] = []        # 告警（超限/超大小/跨域跳过/缺失chunk）
        self.css_count = 0
        # HTML 引用的静态资源清单（含 config.js 等，用于生成资源条目）
        self.resource_refs: list[dict] = []  # [{url, ref, kind: js/css}]
        # 本地模式：无法解析的 chunk（缺失文件）记录，便于人工补齐
        self.missing_chunks: list[str] = []
        if self.local_mode:
            self.root = Path(target).resolve()

    # ==================== 网络模式：底层请求（仅限公开静态资源本身） ====================
    async def _fetch(self, url: str) -> bytes | None:
        """下载单个资源。任何失败返回 None 且不影响整体任务。"""
        if self.resource_count >= MAX_RESOURCE_COUNT:
            self.warnings.append(f"资源总数已达上限 {MAX_RESOURCE_COUNT}，停止采集")
            return None
        if url in self.visited:
            return None
        self.visited.add(url)

        # 铁律：默认只采集同域资源
        if not ALLOW_CROSS_ORIGIN_STATIC and not same_origin(self.target, url):
            self.warnings.append(f"跳过跨域静态资源（默认关闭跨域采集）: {url}")
            return None

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                limits=httpx.Limits(max_connections=8),
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                body = resp.content
        except httpx.HTTPStatusError as exc:
            logger.warning("资源状态异常 %s -> %s", url, exc.response.status_code)
            return None
        except Exception as exc:
            logger.debug("资源请求失败 %s: %s", url, exc)
            return None

        self.resource_count += 1
        if len(body) > MAX_FILE_SIZE:  # 第1道保护：单文件 2MB
            self.warnings.append(f"文件超限跳过（>2MB）: {url}")
            logger.warning("文件超限跳过: %s (%d bytes)", url, len(body))
            return None
        return body

    # ==================== HTML 解析（两种模式共用） ====================
    def _links_from_html(self, html: str, base: str) -> tuple[list[str], list[str]]:
        """提取 HTML 中的 JS 与 CSS 链接，并解析内联脚本中的动态 import。"""
        soup = BeautifulSoup(html, "html.parser")
        js_urls, css_urls = [], []
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "").strip()
            if src:
                js_urls.append(normalize_url(base, src))
        for tag in soup.find_all("link", href=True):
            rel = " ".join(tag.get("rel", [])).lower()
            href = tag.get("href", "").strip()
            if "stylesheet" in rel and href:
                css_urls.append(normalize_url(base, href))
        # 内联脚本里的动态 import（SPA 常见：<script>import('./chunk.js')</script>）
        for raw in soup.find_all("script"):
            if raw.string:
                js_urls.extend(self._dynamic_chunks_from_js(raw.string, base))
        return js_urls, css_urls

    def _dynamic_chunks_from_js(self, code: str, base: str) -> list[str]:
        """从 JS 源码中发现动态 chunk 的 URL 列表（支持 http(s)、/ 绝对、./ 相对）。"""
        found: list[str] = []
        for pattern in (_IMPORT_LITERAL_RE, _STATIC_IMPORT_RE, _SIDE_EFFECT_IMPORT_RE):
            for match in pattern.finditer(code):
                spec = match.group(1).strip()
                if not spec:
                    continue
                if spec.startswith(("http://", "https://", "./", "../", "/")):
                    found.append(normalize_url(base, spec))
                # 其他写法（如 import(variable) 动态变量）无法静态解析，记录提示
        return found

    # ==================== 保存原始 JS 备份 ====================
    def _save_raw(self, url: str, text: str) -> None:
        if self.raw_dir is None:
            return
        try:
            digest = hashlib.sha256(url.encode()).hexdigest()[:12]
            last = url.split("/")[-1].split("?")[0][:40] or "chunk"
            if not last.lower().endswith((".js", ".mjs", ".cjs")):
                last += ".js"
            name = f"{digest}-{last}"
            (self.raw_dir / name).write_text(text, encoding="utf-8")
        except OSError as exc:
            logger.debug("raw_js 备份失败 %s: %s", url, exc)

    # ==================== 网络模式：递归扫描 ====================
    async def _scan(self, url: str, depth: int = 0) -> None:
        if depth > MAX_RECURSIVE_DEPTH:  # 第2道保护：递归深度 10
            self.warnings.append(f"递归深度超过 {MAX_RECURSIVE_DEPTH}，停止: {url}")
            return
        body = await self._fetch(url)
        if body is None:
            return
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return

        lower = url.lower()
        is_html = lower.endswith(_HTML_EXT) or text.lstrip().lower().startswith(("<!doctype", "<html"))
        is_js = lower.endswith(_JS_EXT) or _looks_like_js(text)

        if is_html:
            js_urls, css_urls = self._links_from_html(text, url)
            for js_url in js_urls:
                self.resource_refs.append({"url": js_url, "ref": url, "kind": "js"})
                await self._scan(js_url, depth + 1)
            # CSS 仅下载存证（不参与业务链路解析）
            for css_url in css_urls:
                self.resource_refs.append({"url": css_url, "ref": url, "kind": "css"})
                if await self._fetch(css_url) is not None:
                    self.css_count += 1
        elif is_js:
            self.js_store[url] = text
            self._save_raw(url, text)
            for chunk in self._dynamic_chunks_from_js(text, url):
                await self._scan(chunk, depth + 1)
        else:
            logger.debug("非 JS/HTML 资源，仅下载存证: %s", url)

    # ==================== 本地目录模式（零网络请求） ====================
    def _local_locate(self, vurl: str) -> Path | None:
        """虚拟 URL -> 本地文件：
        1) root 下按 URL 路径直查；2) 找不到则按 basename 全树唯一匹配
        （容忍 assets/ 等目录前缀差异）。
        绝对 URL（http/https）自动提取 path 部分；这是 CDN 分离架构
        （页面在 A 域、静态资源在 B 域）本地审计的必要支持。"""
        if not vurl or vurl.startswith(("data:", "javascript:")):
            return None
        if vurl.startswith(("http://", "https://")):
            rel = urlparse(vurl).path.lstrip("/")
            if not rel:
                return None
        else:
            rel = vurl.lstrip("/")
        direct = self.root / rel
        if direct.is_file():
            return direct
        name = Path(rel).name
        if name:
            hits = [p for p in self.root.rglob(name) if p.is_file()]
            if hits:
                if len(hits) > 1:
                    self.warnings.append(f"本地存在多个同名文件 {name}，取第一个: {hits[0]}")
                return hits[0]
        return None

    def _local_read(self, vurl: str) -> str | None:
        """本地读取文件内容（含单文件大小保护）。缺失则记入 missing_chunks。"""
        path = self._local_locate(vurl)
        if path is None:
            self.missing_chunks.append(vurl)
            logger.warning("[本地模式] 缺失 chunk/资源: %s", vurl)
            return None
        try:
            if path.stat().st_size > MAX_FILE_SIZE:  # 第1道保护：单文件 2MB
                self.warnings.append(f"文件超限跳过（>{MAX_FILE_SIZE}字节）: {vurl}")
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("本地读取失败 %s: %s", vurl, exc)
            return None

    def _local_scan(self, vurl: str, depth: int = 0) -> None:
        """本地目录模式递归扫描（同步；与网络模式共用解析逻辑）。"""
        if depth > MAX_RECURSIVE_DEPTH:  # 第2道保护
            self.warnings.append(f"递归深度超过 {MAX_RECURSIVE_DEPTH}，停止: {vurl}")
            return
        if self.resource_count >= MAX_RESOURCE_COUNT:  # 第3道保护
            self.warnings.append(f"资源总数已达上限 {MAX_RESOURCE_COUNT}，停止采集")
            return
        if vurl in self.visited:
            return
        self.visited.add(vurl)
        self.resource_count += 1

        text = self._local_read(vurl)
        if text is None:
            return
        lower = vurl.lower()
        is_html = lower.endswith(_HTML_EXT) or text.lstrip().lower().startswith(("<!doctype", "<html"))
        is_js = lower.endswith(_JS_EXT) or _looks_like_js(text)

        if is_html:
            js_urls, css_urls = self._links_from_html(text, vurl)  # base 用虚拟 URL
            for js_url in js_urls:
                self.resource_refs.append({"url": js_url, "ref": vurl, "kind": "js"})
                self._local_scan(js_url, depth + 1)
            for css_url in css_urls:
                self.resource_refs.append({"url": css_url, "ref": vurl, "kind": "css"})
                if self._local_read(css_url) is not None:
                    self.css_count += 1
        elif is_js:
            self.js_store[vurl] = text
            self._save_raw(vurl, text)
            for chunk in self._dynamic_chunks_from_js(text, vurl):
                self._local_scan(chunk, depth + 1)

    def _local_run(self) -> None:
        """本地模式入口：先找入口 HTML（优先 index.html），再递归解析；无 HTML 则直接解析全部 JS。"""
        html_candidates = sorted(
            self.root.rglob("*.html"),
            key=lambda p: ("index.html" not in p.name, str(p)),
        )
        if html_candidates:
            for html in html_candidates:
                vurl = "/" + str(html.relative_to(self.root)).replace(os.sep, "/")
                self._local_scan(vurl, 0)
        else:
            logger.warning("本地目录中未找到 HTML 文件，直接解析全部 JS 文件")
            for path in sorted(self.root.rglob("*.js")):
                vurl = "/" + str(path.relative_to(self.root)).replace(os.sep, "/")
                self._local_scan(vurl, 0)

    # ==================== 入口 ====================
    async def run(self) -> dict[str, str]:
        """执行采集（自动选择模式），返回 {url: JS源码}。"""
        if self.local_mode:
            logger.info("===== 本地目录模式 target=%s（零网络请求） =====", self.root)
            self._local_run()
        else:
            await self._scan(self.target)

        for warning in self.warnings:
            logger.warning("[采集告警] %s", warning)
        logger.info(
            "采集完成（%s）：JS %d 个，CSS %d 个，HTML资源引用 %d 条，访问/读取 %d 次，缺失 chunk %d 个",
            "本地目录" if self.local_mode else "网络",
            len(self.js_store), self.css_count, len(self.resource_refs),
            len(self.visited), len(self.missing_chunks),
        )
        return self.js_store

    def skipped(self) -> list[str]:
        return self.warnings
