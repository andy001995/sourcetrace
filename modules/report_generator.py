# modules/report_generator.py
# 阶段5：报告生成
# 输出 Markdown 报告（概览 + 链路详情 + 统计），并落盘 interfaces.json / chains.json。
# 所有风险统一标注【静态源码推断，未实测】。
import json
from datetime import datetime
from pathlib import Path

from config import OUTPUT_DIR
from utils.logger import logger


class ReportGenerator:
    """报告生成器。"""

    def __init__(self, interfaces: list[dict], chains: list[dict],
                 extra: dict | None = None):
        self.interfaces = interfaces
        self.chains = chains
        self.extra = extra or {}
        self.extra.setdefault("base_urls", [])

    # ==================== JSON 落盘 ====================
    def save_json(self, output_dir: str | Path | None = None) -> Path:
        out = Path(output_dir) if output_dir else OUTPUT_DIR
        out.mkdir(parents=True, exist_ok=True)
        meta = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target": self.extra.get("target", ""),
            "task_id": self.extra.get("task_id", ""),
            "llm_note": self.extra.get("llm_note", ""),
            "base_urls": self.extra.get("base_urls", []),
            "local_mode": self.extra.get("local_mode", False),
            "missing_chunks": self.extra.get("missing_chunks", []),
            "crashed_files": self.extra.get("crashed_files", []),
            "secrets": self.extra.get("secrets", []),
        }
        (out / "interfaces.json").write_text(
            json.dumps({"meta": meta, "interfaces": self.interfaces},
                       ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "chains.json").write_text(
            json.dumps({"meta": meta, "chains": self.chains},
                       ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("JSON 已落盘: %s, %s", out / "interfaces.json", out / "chains.json")
        return out

    @staticmethod
    def _conf_label(item: dict) -> str:
        """置信度展示映射：AST/封装=高；正则/资源/jsluice=低。"""
        t = item.get("extract_type")
        if t in ("ast", "ast_wrapper"):
            return "高（AST）"
        if t == "resource":
            return "低（配置资源）"
        if t == "regex_wrapper":
            return "低（封装正则）"
        if t == "jsluice":
            return "低（jsluice）"
        return "低（正则）"

    # ==================== Markdown 报告 ====================
    def build_markdown(self, target: str = "") -> str:
        md = []
        md.append("# 前端静态源码业务链路分析报告\n")
        md.append(f"> 目标站点：{target or self.extra.get('target', '')}")
        md.append(f"> 任务ID：{self.extra.get('task_id', '-')}")
        md.append(f"> 生成时间：{datetime.now().isoformat(timespec='seconds')}\n")
        md.append("> ⚠️ **边界声明**：本报告全部结论均基于**公开静态源码**（HTML/JS/配置）静态推断而来，"
                  "未对任何接口发包、未扫描端口、未做漏洞验证；所有风险【静态源码推断，未实测】。"
                  "接口连通性测试、漏洞验证与业务伤害判定必须由人工完成。\n")

        # ---------- 一、概览 ----------
        ast_cnt = sum(1 for i in self.interfaces if i.get("extract_type") in ("ast", "ast_wrapper"))
        regex_cnt = sum(1 for i in self.interfaces
                        if i.get("extract_type") in ("regex", "regex_member", "regex_wrapper", "jsluice", "resource"))
        secrets = self.extra.get("secrets", [])
        md.append("## 一、概览\n")
        md.append("| 指标 | 数值 |")
        md.append("| --- | --- |")
        md.append(f"| 静态资源（JS） | {self.extra.get('js_count', '-')} 个 |")
        md.append(f"| 提取接口总数 | {len(self.interfaces)} 条 |")
        md.append(f"| AST 直接命中（高置信） | {ast_cnt} 条 |")
        md.append(f"| 正则/资源兜底（低置信） | {regex_cnt} 条 |")
        md.append(f"| 业务链路 | {len(self.chains)} 条 |")
        md.append(f"| LLM 语义分析 | {self.extra.get('llm_note', 'LLM 语义分析未启用（可选），漏洞类型映射基于关键词规则，准确率有限，建议配置 LLM 后重跑')} |")
        if secrets:
            md.append(f"| 硬编码敏感密钥【静态源码推断，未实测】 | {len(secrets)} 处 |")
        crashed = self.extra.get("crashed_files", [])
        if crashed:
            md.append(f"| tree-sitter 子进程崩溃/超时降级文件 | {len(crashed)} 个（已自动降级 esprima） |")
        if self.extra.get("base_urls"):
            md.append("| baseURL 配置 | " + "、".join(self.extra["base_urls"][:5]) + " |")
        md.append("")
        if self.extra.get("collector_warnings"):
            md.append("**采集告警**：")
            for w in self.extra["collector_warnings"][:20]:
                md.append(f"- {w}")
            md.append("")

        # ---------- 硬编码敏感密钥区块 ----------
        if secrets:
            md.append("## 附：硬编码敏感密钥【静态源码推断，未实测】\n")
            md.append("| 密钥/凭据名 | 值 | 来源（文件:行） | 风险方向 |")
            md.append("| --- | --- | --- | --- |")
            for s in secrets:
                risk = ("硬编码敏感密钥，若服务端直接信任该值，可能导致认证绕过、会话伪造或越权；"
                        "是否可利用需人工实测确认")
                md.append(f"| {s['name']} | `{s['value']}` | {s['source_file']} | {risk} |")
            md.append("")

        # ---------- tree-sitter 子进程崩溃/超时降级文件 ----------
        crashed = self.extra.get("crashed_files", [])
        if crashed:
            md.append("## 附：tree-sitter 子进程崩溃/超时文件（已自动降级）\n")
            md.append("tree-sitter（C 扩展）在解析以下文件时子进程发生崩溃/超时；为保证任务不中断，"
                      "这些文件已自动降级为纯 Python 的 esprima 解析（含正则兜底），其余文件未受影响：\n")
            md.append("| 文件 | 崩溃/超时原因 |")
            md.append("| --- | --- |")
            for c in crashed:
                md.append(f"| `{c.get('file','')}` | {c.get('reason','')} |")
            md.append("\n> 说明：进程隔离确保单个文件解析崩溃不会终止整个任务；如需更高覆盖率，"
                      "可升级 tree-sitter/tree-sitter-javascript 版本后重跑。\n")

        # ---------- 缺失 chunk（本地模式） ----------
        missing = self.extra.get("missing_chunks", [])
        if missing:
            md.append("## 附：未解析的 chunk（本地模式文件缺失）\n")
            md.append("以下被 JS 引用的文件在本地目录中不存在，其中可能包含更多接口：\n")
            for chunk in missing[:30]:
                md.append(f"- `{chunk}`")
            md.append("\n> 提示：补齐缺失文件后重新运行，接口覆盖即可补全（本工具不会编造缺失内容）。\n")

        # ---------- 二、业务链路详情 ----------
        md.append("## 二、业务链路详情\n")
        for chain in self.chains:
            md.append(self._chain_block(chain))

        # ---------- 三、接口清单统计 ----------
        md.append("## 三、接口清单统计\n")
        md.append("| # | 方法 | 接口路径 | 参数（源码可见） | 置信度 | 来源（文件:行） |")
        md.append("| --- | --- | --- | --- | --- | --- |")
        for idx, item in enumerate(self.interfaces, start=1):
            params = "、".join(item.get("params") or []) or "-"
            sources = "、".join(item.get("source_files") or [item.get("source_file", "-")])
            conf = self._conf_label(item)
            md.append(f"| {idx} | {item['method']} | `{item['url']}` | {params} | {conf} | {sources} |")
        md.append("")

        # ---------- 四、人工验证与边界 ----------
        md.append("## 四、人工验证要求与使用边界\n")
        md.append("1. 人工负责全部接口连通性测试、漏洞验证、业务伤害判定；")
        md.append("2. 所有风险结论在实测前一律视为【静态源码推断，未实测】；")
        md.append("3. 本工具零主动探测发包：不向提取接口发包、不扫描端口、不 Fuzz、不爆破；")
        md.append("4. 使用者必须持有目标站点书面授权。\n")

        return "\n".join(md)

    # ==================== 单条链路模板 ====================
    def _chain_block(self, chain: dict) -> str:
        flow = chain["data_flow"]
        tv = chain["target_value"]
        vm = chain["vuln_mapping"]
        lines = [
            f"【链路编号】{chain['link_id']}",
            f"▸ 业务起点：{chain['business_start']}",
            f"▸ 调用核心接口：{chain['core_api']}",
            "▸ 数据流走向",
            f"  输入：{flow['input']}",
            f"  流向：{flow['flow']}",
            f"  输出：{flow['output']}",
            "▸ 目标价值",
            f"  红队关注度：{tv['red']}",
            f"  白帽关注度：{tv['white']}",
            "▸ 漏洞类型映射",
            f"  族：{vm['family']} → {vm['sub']}",
            f"  危害：{vm['harm']}",
            "▸ 链路关联接口",
        ]
        if chain["related_api"]:
            for rel in chain["related_api"]:
                lines.append(f"  - {rel['api']}（{rel['role']}）")
        else:
            lines.append("  - （未发现明确的前置/后置依赖，需人工确认）")
        lines.append("▸ 静态推导风险【静态源码推断，未实测】")
        for risk in chain["static_risk"]:
            lines.append(f"  - {risk}")
        lines.append("▸ 人工验证任务清单")
        for idx, task in enumerate(chain["verify_tasks"], start=1):
            lines.append(f"  {idx}. {task}")
        lines.append(f"▸ 置信度：{chain['confidence']}")
        lines.append("")
        return "\n".join(lines)

    # ==================== 一键生成 ====================
    def generate(self, target: str, output_dir: str | Path | None = None) -> tuple[Path, str]:
        out = self.save_json(output_dir)
        md = self.build_markdown(target)
        (out / "report.md").write_text(md, encoding="utf-8")
        logger.info("报告已生成: %s", out / "report.md")
        return out, md
