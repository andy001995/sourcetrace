# modules/llm_analyzer.py
# 阶段3b：LLM 语义分析
#
# 严格规则（防幻觉，代码级保证）：
#   1) 禁止编造不存在接口/参数/风险 —— LLM 输出中凡 url+method 不在 AST 接口清单内的条目一律丢弃；
#   2) 只能基于 AST 结果 + JS 上下文分析 —— Prompt 中只给接口清单与源码上下文；
#   3) 无法判断时置信度标"低"，不强行猜测；
#   4) 输出 JSON 固定 schema，解析失败自动降级为 AST/正则结果。
#
# Provider 抽象：auto（默认，可插拔）/ openai（OpenAI 兼容协议）/ ollama（本地模型）/ mock（内置启发式）/ off（关闭）
import asyncio
import json
import re

import httpx

from config import (
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_MODEL,
    LLM_PROVIDER,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
)
from utils.logger import logger

# LLM 未启用时写入报告的统一说明文案（可选功能 + 关键词规则准确率有限提示）
LLM_DISABLED_NOTE = (
    "LLM 语义分析未启用（可选），漏洞类型映射基于关键词规则，"
    "准确率有限，建议配置 LLM 后重跑"
)

# LLM 输出固定 schema 提示（随请求下发给模型）
SCHEMA_PROMPT = """
请仅输出一个 JSON 对象，schema 严格如下（不要输出任何解释文字）：
{
  "interface_meta": [
    {
      "url": "接口路径(与清单完全一致)",
      "method": "HTTP方法(与清单完全一致)",
      "business_desc": "接口的业务功能描述(基于JS上下文推断)",
      "layer": "接口所属分层: 前端/网关/业务服务/第三方服务",
      "risk_direction": "风险方向: 命令执行/注入/文件操作/认证缺陷/敏感信息/越权/无明确风险/需人工研判",
      "confidence": "高/中/低(无法判断必须写低)"
    }
  ],
  "call_relation": [
    {"prev": ["方法","路径"], "next": ["方法","路径"]}
  ]
}
约束：
- url/method 只能从清单中选择，禁止编造清单之外的接口；
- call_relation 表示调用顺序依赖（prev 先于 next 发生），同样只能引用清单中的接口；
- 无法从上下文判断的内容，confidence 一律写"低"。
"""


class LLMAnalyzer:
    """LLM 语义分析器（接口抽象，可切换 Provider）。"""

    def __init__(self, interfaces: list[dict], js_store: dict[str, str],
                 provider: str | None = None):
        self.interfaces = interfaces
        self.js_store = js_store
        # 支持调用方（CLI 参数 / 网页服务）显式覆盖 Provider；未指定则读环境配置
        self.provider = (provider or LLM_PROVIDER or "auto").lower()

    def _resolve_provider(self) -> str:
        """可插拔判定：把配置的 provider 解析为真正执行的 provider。
        - auto：配置了 LLM_API_KEY 才启用 openai，否则关闭（默认零 LLM 请求）；
        - openai 但无 Key：安全降级为 off（绝不带空 Key 发包）；
        - ollama / mock / off：原样返回。
        """
        p = self.provider
        if p == "auto":
            return "openai" if LLM_API_KEY else "off"
        if p == "openai" and not LLM_API_KEY:
            logger.warning("LLM_PROVIDER=openai 但未配置 LLM_API_KEY，安全降级为 off（不发起 LLM 请求）")
            return "off"
        return p

    # ==================== 入口 ====================
    async def run(self) -> dict:
        if not self.interfaces:
            return self._fallback_result("接口清单为空，跳过 LLM 分析")
        effective = self._resolve_provider()
        if effective == "off":
            logger.info("LLM 语义分析未启用（可选）：仅用 AST/正则 + 关键词规则映射")
            return self._fallback_result(LLM_DISABLED_NOTE)
        if effective == "mock":
            return self._mock_meta()
        if effective == "ollama":
            raw = await self._ask_ollama()
        else:  # openai / 其他 OpenAI 兼容服务
            raw = await self._ask_openai()
        return self._normalize(raw)

    # ==================== 降级 ====================
    def _fallback_result(self, note: str) -> dict:
        return {"interface_meta": [], "call_relation": [], "llm_note": note}

    # ==================== mock（内置启发式，离线演示/测试） ====================
    def _mock_meta(self) -> dict:
        """本地启发式规则生成业务描述，不发任何网络请求。仅供离线演示/测试。"""
        logger.info("LLM Provider=mock，使用内置启发式规则")
        meta = []
        for item in self.interfaces:
            url = item["url"].lower()
            method = item["method"].upper()
            desc, layer, risk = self._heuristic(item)
            meta.append({
                "url": item["url"], "method": method,
                "business_desc": desc, "layer": layer,
                "risk_direction": risk, "confidence": "中",
            })
        return {"interface_meta": meta, "call_relation": [],
                "llm_note": "mock 启发式分析（非真实 LLM，仅用于离线演示/测试）"}

    def _heuristic(self, item: dict) -> tuple[str, str, str]:
        """极简路径启发式：仅供 mock 使用，明确标注为推断。"""
        url, method = item["url"].lower(), item["method"].upper()
        if "login" in url or "auth" in url or "token" in url:
            return "认证/登录相关接口", "业务服务", "认证缺陷（需人工研判）"
        if "admin" in url or "manage" in url or "config" in url or "setting" in url:
            return "管理/配置类接口", "业务服务/管理面", "越权或未授权访问方向（需人工研判）"
        if "upload" in url or "file" in url:
            return "文件操作类接口", "业务服务", "文件上传/读写方向（需人工研判）"
        if "user" in url or "member" in url or "account" in url:
            return "用户数据类接口", "业务服务", "敏感信息方向（需人工研判）"
        if "list" in url or "search" in url or "query" in url:
            return "查询/列表类接口", "业务服务", "无明确风险或越权查询（需人工研判）"
        return f"{method} 业务接口（静态推断）", "业务服务", "需人工研判"

    # ==================== OpenAI 兼容 ====================
    async def _ask_openai(self) -> str | None:
        if not LLM_API_KEY:
            logger.warning("LLM_API_KEY 未配置，LLM 语义分析降级（跳过）")
            return None
        payload = {
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": SCHEMA_PROMPT},
                {"role": "user", "content": self._build_user_prompt()},
            ],
            "temperature": 0.1,
        }
        headers = {"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"}
        url = f"{LLM_BASE_URL.rstrip('/')}/chat/completions"
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.error("OpenAI 兼容调用失败，降级: %s", exc)
            return None

    # ==================== Ollama（本地模型） ====================
    async def _ask_ollama(self) -> str | None:
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": SCHEMA_PROMPT},
                {"role": "user", "content": self._build_user_prompt()},
            ],
            "stream": False,
            "format": "json",
        }
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
        try:
            async with httpx.AsyncClient(timeout=180) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")
        except Exception as exc:
            logger.error("Ollama 调用失败，降级: %s", exc)
            return None

    # ==================== Prompt 组装与结果归一化 ====================
    def _build_user_prompt(self) -> str:
        lines = ["以下是前端静态源码 AST 提取的接口清单（json）：", json.dumps(
            [{"method": i["method"], "url": i["url"], "params": i.get("params", [])}
             for i in self.interfaces], ensure_ascii=False)]
        lines.append("\nJS 源码上下文（截断）：")
        ctx_total, limit = [], 8000
        for src_url, code in self.js_store.items():
            ctx_total.append(f"--- {src_url} ---\n{code[:1200]}")
            if sum(len(c) for c in ctx_total) >= limit:
                break
        lines.append("\n".join(ctx_total)[:limit])
        lines.append("\n请按 schema 输出 JSON。")
        return "\n".join(lines)

    def _normalize(self, raw: str | None) -> dict:
        """解析 LLM JSON；防幻觉：仅保留清单中真实存在的接口。"""
        if not raw:
            return self._fallback_result("LLM 返回为空，降级使用 AST/正则结果")
        parsed = self._parse_json(raw)
        if parsed is None:
            return self._fallback_result("LLM JSON 解析失败，降级使用 AST/正则结果")

        valid_keys = {(i["method"].upper(), i["url"]) for i in self.interfaces}
        meta_out, rel_out = [], []

        for entry in parsed.get("interface_meta", []) or []:
            try:
                method = str(entry.get("method", "")).upper()
                url = str(entry.get("url", ""))
            except Exception:
                continue
            if (method, url) not in valid_keys:
                continue  # 防幻觉：丢弃清单之外的接口
            confidence = entry.get("confidence") if entry.get("confidence") in ("高", "中", "低") else "低"
            meta_out.append({
                "url": url, "method": method,
                "business_desc": str(entry.get("business_desc") or "（LLM 未描述）"),
                "layer": str(entry.get("layer") or "未知分层"),
                "risk_direction": str(entry.get("risk_direction") or "需人工研判"),
                "confidence": confidence,
            })

        for rel in parsed.get("call_relation", []) or []:
            prev = rel.get("prev") or []
            nxt = rel.get("next") or []
            if isinstance(prev, list) and len(prev) == 2 and isinstance(nxt, list) and len(nxt) == 2:
                key_prev = (str(prev[0]).upper(), str(prev[1]))
                key_next = (str(nxt[0]).upper(), str(nxt[1]))
                if key_prev in valid_keys and key_next in valid_keys:
                    rel_out.append({"prev": list(key_prev), "next": list(key_next)})

        logger.info("LLM 分析完成：有效接口 %d 条 / 调用关系 %d 条", len(meta_out), len(rel_out))
        return {"interface_meta": meta_out, "call_relation": rel_out,
                "llm_note": "LLM 语义分析完成"}

    @staticmethod
    def _parse_json(text: str) -> dict | None:
        """宽容解析 LLM 输出中的 JSON（去除代码围栏、截取首个花括号平衡块）。"""
        t = text.strip()
        if t.startswith("```"):
            t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.I)
            t = re.sub(r"\s*```$", "", t)
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            pass
        # 截取从第一个 { 到最后一个 } 的片段再试
        start, end = t.find("{"), t.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(t[start:end + 1])
            except json.JSONDecodeError:
                pass
        return None
