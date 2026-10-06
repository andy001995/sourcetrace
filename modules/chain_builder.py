# modules/chain_builder.py
# 阶段4：业务链路组装
# 按固定模板（见 README【六】）组织每条业务链路，标注依赖关系。
# 风险族映射仅基于路径/风险关键词做【静态推断提示】，绝不作为结论；无法命中时明确写"需人工研判"。
# 规则按"特异性从高到低"排序：XXE/SSTI/表达式注入等强信号必须排在 admin/config 等泛化大类之前，
# 否则 /api/admin/xml/parse 会被 "admin" 抢先误判为越权。
import re
from utils.logger import logger

# 风险关键词 -> (漏洞族, 子类, 危害, 红队关注度, 白帽关注度)
# 说明：这是纯静态推断的提示映射，最终判定必须由人工完成。
_RISK_RULES = [
    (("spel", "ognl", "jexl", "表达式", "eval", "evaluate", "el-injection"),
     ("注入族", "表达式注入（SpEL/OGNL 等）", "RCE（严重）", "🔥🔥🔥", "🔥🔥🔥")),
    (("xxe", "xml", "sax", "documentbuilder", "xmlreader", "saxreader"),
     ("注入族", "XML 外部实体注入（XXE）", "文件读取/SSRF/RCE（高~严重）", "🔥🔥🔥", "🔥🔥🔥")),
    (("ssti", "template", "freemarker", "velocity", "thymeleaf", "jinja", "twig"),
     ("注入族", "服务端模板注入（SSTI）", "RCE（严重）", "🔥🔥🔥", "🔥🔥🔥")),
    (("command", "命令", "exec", "system", "shell", "popen", "child_process"),
     ("注入族", "命令注入", "RCE（严重）", "🔥🔥🔥", "🔥🔥🔥")),
    (("sql", "jdbc", "select from", "insert into", "update set", "delete from"),
     ("注入族", "SQL 注入", "数据泄露/篡改（严重）", "🔥🔥🔥", "🔥🔥🔥")),
    (("upload", "上传", "import", "importdata"),
     ("文件族", "文件导入/任意文件上传", "getshell（严重）", "🔥🔥🔥", "🔥🔥🔥")),
    (("download", "下载", "file", "read", "path", "目录", "遍历"),
     ("文件族", "任意文件读取/路径穿越", "敏感文件泄露（高）", "🔥🔥", "🔥🔥")),
    (("token", "jwt", "cookie", "session", "auth", "password", "密码", "密钥", "secret", "apikey"),
     ("认证族", "认证/会话/密钥泄露", "越权或凭据泄露（中高）", "🔥🔥", "🔥🔥")),
    (("admin", "manage", "管理", "后台", "config", "setting", "配置"),
     ("权限族", "越权/未授权访问", "数据泄露（中）", "🔥🔥", "🔥🔥")),
    (("debug", "test", "mock", "internal", "内部"),
     ("暴露面族", "调试/测试接口暴露", "信息泄露（中低）", "🔥", "🔥🔥")),
]

# 默认人工验证任务清单（可针对具体接口生成）
_DEFAULT_VERIFY_TASKS = (
    "验证 {api} 接口连通性（人工发包测试）",
    "确认入参是否用户可控及可控边界",
    "按风险方向做人工漏洞验证，判定业务伤害等级",
)


class ChainBuilder:
    """按业务交互链路组装输出。"""

    def __init__(self, interfaces: list[dict], llm_result: dict,
                 secrets: list[dict] | None = None):
        self.interfaces = interfaces
        self.meta = llm_result.get("interface_meta", [])
        self.relations = llm_result.get("call_relation", [])
        self.llm_note = llm_result.get("llm_note", "")
        # 硬编码敏感密钥（用于把密钥来源文件关联到对应链路的风险提示）
        self.secrets = secrets or []

    # ==================== 入口 ====================
    def build(self) -> list[dict]:
        meta_by_key = {(m.get("method", "GET").upper(), m.get("url", "")): m for m in self.meta}
        chains = []
        for idx, api in enumerate(self.interfaces, start=1):
            key = (api.get("method", "GET").upper(), api.get("url", ""))
            meta = meta_by_key.get(key, {})
            chains.append(self._build_chain(idx, api, meta))
        logger.info("业务链路组装完成：%d 条（LLM 注：%s）", len(chains), self.llm_note or "无")
        return chains

    # ==================== 单链路构建 ====================
    def _build_chain(self, idx: int, api: dict, meta: dict) -> dict:
        method = api.get("method", "GET").upper()
        url = api.get("url", "")
        core_api = f"{method} {url}"

        business_start = meta.get("business_desc") or "待人工研判（LLM 语义分析未启用，基于关键词规则推断）"
        risk_dir = meta.get("risk_direction") or "需人工研判"
        layer = meta.get("layer") or "未知分层"
        confidence = self._confidence_text(api, meta)

        vuln_family, vuln_sub, harm, red, white = self._map_risk(url, risk_dir)
        related = self._related_apis(method, url)
        params = api.get("params") or []

        # 静态推导风险：优先用风险族映射结果；LLM 未启用时补一句映射依据
        if risk_dir and risk_dir != "需人工研判":
            static_risk = [f"{risk_dir}（{'、'.join(params) if params else '入参待确认'}）"]
        else:
            static_risk = [
                f"{vuln_sub}（静态推断提示，基于路径/参数关键词；"
                f"{'、'.join(params) if params else '入参待确认'}）"
            ]
        # 若该接口来源文件含硬编码敏感密钥，追加关联提示
        file_hint = self._secret_file_hint(api)
        if file_hint:
            static_risk.append(file_hint)

        return {
            "link_id": f"Link-{idx:03d}",
            "business_start": business_start,
            "core_api": core_api,
            "data_flow": {
                "input": "、".join(params) if params else "（入参未从源码确认，需人工确认）",
                "flow": f"前端 → 网关 → {url} → 后端业务处理",
                "output": "（响应结构未知，需人工验证）",
            },
            "target_value": {
                "red": red,
                "white": white,
            },
            "vuln_mapping": {
                "family": vuln_family,
                "sub": vuln_sub,
                "harm": harm,
            },
            "layer": layer,
            "related_api": related,
            "static_risk": static_risk,
            "verify_tasks": [t.format(api=core_api) for t in _DEFAULT_VERIFY_TASKS],
            "confidence": confidence,
            "source_files": api.get("source_files", []),
        }

    def _secret_file_hint(self, api: dict) -> str:
        """若接口来源文件与某个硬编码密钥同文件，返回关联提示（否则空串）。
        匹配方式：接口 source_file 与密钥 source_file 的路径前缀互相匹配
        （resource 条目形如 '/config.js（HTML引用自 /index.html）'）。"""
        if not self.secrets:
            return ""
        src = (api.get("source_files") or [api.get("source_file") or ""])
        hits = []
        for s in self.secrets:
            secret_file = (s.get("source_file") or "").split(":")[0]
            if not secret_file:
                continue
            for sf in src:
                if sf.startswith(secret_file) or secret_file.startswith(sf):
                    hits.append(f"{s.get('name')}={s.get('value')}")
                    break
        if not hits:
            return ""
        return f"来源文件含硬编码敏感密钥（{'、'.join(hits)}）【静态源码推断，未实测】"

    # ==================== 置信度 ====================
    @staticmethod
    def _confidence_text(api: dict, meta: dict) -> str:
        """置信度规则：高（AST 命中）/ 中（LLM 推断）/ 低（正则兜底）。
        ast_wrapper 为 AST 封装修饰（高）；regex* / jsluice / resource 均为静态兜底（低）；
        只有 LLM 真正分析过（meta 有业务描述）才标中。"""
        extract_type = api.get("extract_type", "")
        if extract_type in ("ast", "ast_wrapper"):
            return "高（AST 直接命中）"
        if extract_type in ("regex", "regex_member", "regex_wrapper", "jsluice"):
            return "低（正则兜底）"
        if extract_type == "resource":
            return "低（配置资源）"
        if meta.get("business_desc"):
            return "中（LLM 推断）"
        return "低（静态兜底）"

    # ==================== 风险族映射（静态推断提示） ====================
    @staticmethod
    def _kw_hit(blob: str, kw: str) -> bool:
        """关键词命中判断。
        - 纯 ASCII 关键词：按单词边界匹配，避免 pro"file" 这类子串误伤
          （file 前一个字符是字母 o，不算命中；/file/import 前是 / 才算命中）；
        - 含中文等非 ASCII 关键词：直接子串匹配（中文无单词边界概念）。
        """
        if kw.isascii():
            return re.search(r"(?<![0-9a-zA-Z])" + re.escape(kw) + r"(?![0-9a-zA-Z])", blob) is not None
        return kw in blob

    def _map_risk(self, url: str, risk_dir: str) -> tuple[str, str, str, str, str]:
        blob = f"{url.lower()} {risk_dir.lower()}"
        for keywords, result in _RISK_RULES:
            if any(self._kw_hit(blob, k) for k in keywords):
                return result
        return ("未知族", "需人工研判", "需人工验证确认", "🔥", "🔥")

    # ==================== 链路关联接口 ====================
    def _related_apis(self, method: str, url: str) -> list[dict]:
        """依据 LLM 调用关系标注前置依赖与后续调用。"""
        key = (method, url)
        prevs, nexts = [], []
        for rel in self.relations:
            if rel.get("next") == list(key):
                prevs.append(rel.get("prev"))
            if rel.get("prev") == list(key):
                nexts.append(rel.get("next"))
        related = []
        for p in prevs:
            related.append({"role": "前置依赖", "api": f"{p[0]} {p[1]}"})
        for n in nexts:
            related.append({"role": "后续调用", "api": f"{n[0]} {n[1]}"})
        return related
