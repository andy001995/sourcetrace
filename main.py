# main.py
# 命令行入口（形态B：一键 exe 的核心；形态C：Docker 亦可调用）
#
# 用法：
#   python main.py --target http://example.com --output ./output/
#   python main.py --target http://example.com --llm-provider ollama --confirm
#   python main.py --target ./internal_static --local --output ./output/   # 本地目录模式，零网络请求
#
# 端到端 5 阶段编排：
#   阶段1 前置准入校验(auth_check) -> 阶段2 静态资源采集(collector)
#   -> 阶段3a AST解析(ast_parser) -> 阶段3b LLM语义分析(llm_analyzer)
#   -> 阶段4 业务链路组装(chain_builder) -> 阶段5 报告生成(report_generator)
import argparse
import asyncio
import os
import sys
from pathlib import Path

from config import OUTPUT_DIR
from utils.logger import logger
from modules.auth_check import cli_confirm, create_task
from modules.collector import ResourceCollector
from modules.ast_parser import ASTApiParser
from modules.llm_analyzer import LLMAnalyzer
from modules.chain_builder import ChainBuilder
from modules.report_generator import ReportGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sourcetrace",
        description="星巡 · 源链（SourceTrace）v1.0 — 前端静态源码业务链路解析工具（纯静态情报分析，零主动探测发包）",
    )
    parser.add_argument("--target", "-t", required=True, help="目标站点地址，如 http://example.com；或本地目录，如 ./internal_static")
    parser.add_argument("--output", "-o", default=str(OUTPUT_DIR), help="报告输出目录（默认 ./output）")
    parser.add_argument("--local", action="store_true",
                        help="本地目录模式：直接读取 target 目录下全部文件，零网络请求（离线测试/审计打包源码）")
    parser.add_argument("--confirm", action="store_true", help="跳过交互确认（已获得书面授权时使用）")
    parser.add_argument("--llm-provider", choices=["auto", "openai", "ollama", "mock", "off"],
                        default=None, help="覆盖 LLM Provider 配置（默认 auto：配置了 API Key 才启用，否则关闭）")
    parser.add_argument("--max-resources", type=int, default=None, help="覆盖最大资源总数（默认500）")
    parser.add_argument("--max-depth", type=int, default=None, help="覆盖递归深度（默认10）")
    return parser.parse_args()


def normalize_target(raw: str, local: bool = False) -> str:
    """目标地址规范化：本地目录直接返回；网络地址自动补全协议。"""
    raw = raw.strip()
    if not raw:
        sys.exit("错误：目标站点地址不能为空")
    # 本地目录模式或显式路径形态：不做协议补全
    if local or os.path.isdir(raw) or raw.startswith(("./", "../")) or raw == ".":
        return raw.rstrip("/")
    if not raw.startswith(("http://", "https://")):
        print("提示：未识别协议，自动补全为 https://")
        raw = "https://" + raw
    return raw.rstrip("/")


async def run_pipeline(target: str, output_dir: Path, provider: str,
                       confirmed: bool = True, task_id: str | None = None,
                       local: bool = False) -> Path:
    """执行端到端 5 阶段，返回报告输出目录。"""

    # ---------- 阶段1：前置准入校验（授权确认已在入口完成，此处落库） ----------
    task_id = task_id or create_task(target, "CLI", confirmed)
    logger.info("===== 阶段1/5 授权确认通过 task_id=%s target=%s =====", task_id, target)

    # ---------- 阶段2：静态资源采集 ----------
    logger.info("===== 阶段2/5 开始静态资源采集（%s） =====",
                "本地目录模式" if local else "网络模式")
    collector = ResourceCollector(target, raw_dir=output_dir / "raw_js", local_mode=local)
    js_store = await collector.run()
    logger.info("===== 阶段2/5 完成：JS %d 个，HTML资源引用 %d 条，缺失 chunk %d 个 =====",
                len(js_store), len(collector.resource_refs), len(collector.missing_chunks))

    # ---------- 阶段3a：AST 源码解析 ----------
    logger.info("===== 阶段3a/5 开始 AST 源码解析 =====")
    parser = ASTApiParser(js_store, resource_refs=collector.resource_refs)
    interfaces = parser.run()

    # ---------- 阶段3b：LLM 语义分析 ----------
    logger.info("===== 阶段3b/5 开始 LLM 语义分析（provider=%s） =====", provider)
    llm_result = await LLMAnalyzer(interfaces, js_store, provider=provider).run()

    # ---------- 阶段4：业务链路组装 ----------
    logger.info("===== 阶段4/5 开始业务链路组装 =====")
    chains = ChainBuilder(interfaces, llm_result, secrets=parser.secrets).build()

    # ---------- 阶段5：报告生成 ----------
    logger.info("===== 阶段5/5 生成报告 =====")
    generator = ReportGenerator(interfaces, chains, extra={
        "target": target,
        "task_id": task_id,
        "js_count": len(js_store),
        "llm_note": llm_result.get("llm_note", ""),
        "base_urls": parser.base_urls,
        "collector_warnings": collector.warnings,
        "secrets": parser.secrets,                # 硬编码敏感密钥
        "crashed_files": parser.crashed_files,    # tree-sitter 子进程崩溃/超时降级文件
        "missing_chunks": collector.missing_chunks,  # 本地模式缺失 chunk
        "resource_refs": collector.resource_refs,    # HTML 静态资源引用
        "js_urls": list(js_store.keys()),            # 已下载 JS（static_assets 下载判定）
        "local_mode": local,
    })
    out, md = generator.generate(target, output_dir)
    print("\n" + "=" * 64)
    print("✅ 分析完成！输出目录：%s" % out)
    print("   - %s" % (out / "interfaces.json"))
    print("   - %s" % (out / "chains.json"))
    print("   - %s" % (out / "report.md"))
    print("=" * 64)
    return out


def main() -> int:
    args = parse_args()
    target = normalize_target(args.target, local=args.local)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 覆盖配置
    if args.max_resources:
        import config as cfg
        cfg.MAX_RESOURCE_COUNT = args.max_resources
    if args.max_depth:
        import config as cfg
        cfg.MAX_RECURSIVE_DEPTH = args.max_depth

    # ---------- 阶段1：授权确认弹窗 ----------
    confirmed = args.confirm or cli_confirm(target)
    if not confirmed:
        print("\n任务已终止：未获得授权确认。本工具要求目标站点书面授权，请勿越权使用。")
        return 1

    provider = args.llm_provider or __import__("config").LLM_PROVIDER
    try:
        asyncio.run(run_pipeline(target, output_dir, provider, confirmed=confirmed,
                                 local=args.local))
    except KeyboardInterrupt:
        print("\n用户中断。")
        return 130
    except Exception as exc:
        logger.exception("任务失败")
        print(f"\n任务失败：{exc}")
        return 1
    return 0


if __name__ == "__main__":
    # PyInstaller 打包后 multiprocessing spawn 需要 freeze_support（必须在最早执行）
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
