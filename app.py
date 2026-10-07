# app.py
# 网页版后端（形态A：主打）
#
# 功能：
#   - POST /api/task      创建任务（须携带授权确认），限流计数，后台异步执行
#   - GET  /api/task/{id} 前端轮询任务进度
#   - GET  /api/task/{id}/report      报告 Markdown 文本
#   - GET  /api/task/{id}/download    下载 report.md
#   - GET  /api/task/{id}/interfaces  接口清单 JSON
#   - GET  /api/task/{id}/chains      业务链路 JSON
#   - GET  /                       单文件前端
#
# 启动：uvicorn app:app --host 0.0.0.0 --port 8000
import asyncio
import json
from datetime import date, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from config import (
    BASE_DIR,
    MAX_TASKS_PER_IP_DAY,
    OUTPUT_DIR,
    TRUST_PROXY,
    WEB_TOKEN,
)
from modules.auth_check import (
    bump_usage,
    create_task,
    get_usage,
    get_web_task,
    upsert_web_task,
)
from modules.ast_parser import ASTApiParser
from modules.chain_builder import ChainBuilder
from modules.collector import ResourceCollector
from modules.llm_analyzer import LLMAnalyzer
from modules.report_generator import ReportGenerator
from utils.logger import logger

app = FastAPI(title="星巡 · 源链（SourceTrace）", description="前端静态源码业务链路解析工具", version="1.0.0")

# 内存态任务进度（供轮询，避免频繁读库）
_TASK_STATE: dict[str, dict] = {}


def _client_ip(request: Request) -> str:
    """获取客户端 IP（可选信任 X-Forwarded-For）。"""
    if TRUST_PROXY and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _auth_ok(request: Request) -> bool:
    """可选访问令牌鉴权（WEB_TOKEN 为空时放行）。"""
    if not WEB_TOKEN:
        return True
    return request.headers.get("x-auth-token", "") == WEB_TOKEN


def _set_state(task_id: str, status: str, progress: int, message: str,
               report_dir: str = "") -> None:
    _TASK_STATE[task_id] = {
        "status": status, "progress": progress, "message": message,
        "report_dir": report_dir,
    }
    upsert_web_task(task_id, status, progress, message, report_dir)


# ==================== 后台任务 ====================
async def run_pipeline(task_id: str, target: str, client_ip: str, out_dir: Path) -> None:
    """异步执行端到端 5 阶段（与 CLI 共用同一套核心引擎）。"""
    _set_state(task_id, "running", 5, "任务已创建，开始执行")
    try:
        # 阶段1：授权记录（Web 端已确认，直接落库）
        create_task(target, client_ip, True)
        _set_state(task_id, "running", 10, "授权确认已记录")

        # 阶段2：静态资源采集
        collector = ResourceCollector(target, raw_dir=out_dir / "raw_js")
        js_store = await collector.run()
        _set_state(task_id, "running", 45, f"静态资源采集完成：JS {len(js_store)} 个")

        # 阶段3a：AST 解析
        parser = ASTApiParser(js_store, resource_refs=collector.resource_refs)
        interfaces = parser.run()
        _set_state(task_id, "running", 60, f"AST 解析完成：提取接口 {len(interfaces)} 个")

        # 阶段3b：LLM 语义分析（Provider 由服务器环境变量统一配置）
        llm_result = await LLMAnalyzer(interfaces, js_store).run()
        _set_state(task_id, "running", 80, "LLM 语义分析完成")

        # 阶段4：业务链路组装
        chains = ChainBuilder(interfaces, llm_result, secrets=parser.secrets).build()
        _set_state(task_id, "running", 90, "业务链路组装完成")

        # 阶段5：报告生成
        generator = ReportGenerator(interfaces, chains, extra={
            "target": target,
            "task_id": task_id,
            "js_count": len(js_store),
            "llm_note": llm_result.get("llm_note", ""),
            "base_urls": parser.base_urls,
            "collector_warnings": collector.warnings,
            "secrets": parser.secrets,
            "crashed_files": parser.crashed_files,
            "missing_chunks": collector.missing_chunks,
            "resource_refs": collector.resource_refs,
            "js_urls": list(js_store.keys()),
        })
        generator.generate(target, out_dir)

        _set_state(task_id, "done", 100, "报告生成完成", report_dir=str(out_dir))
        logger.info("任务完成 task_id=%s output=%s", task_id, out_dir)
    except Exception as exc:
        logger.exception("任务失败 task_id=%s", task_id)
        _set_state(task_id, "failed", 100, f"任务失败：{exc}")


# ==================== API ====================

@app.get("/", response_class=HTMLResponse)
async def index():
    """单文件前端。"""
    html = (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.post("/api/task")
async def create_task_api(request: Request):
    """创建分析任务。必须携带授权确认；按 IP 每日限流。"""
    if not _auth_ok(request):
        raise HTTPException(status_code=401, detail="无效访问令牌")
    body = await request.json()
    target = str(body.get("target", "")).strip()
    confirmed = bool(body.get("confirmed", False))

    if not target:
        raise HTTPException(status_code=400, detail="目标站点地址不能为空")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    if not confirmed:
        raise HTTPException(status_code=400, detail="必须勾选授权确认才能开始分析")

    ip = _client_ip(request)
    day = date.today().isoformat()
    if get_usage(ip, day) >= MAX_TASKS_PER_IP_DAY:
        raise HTTPException(status_code=429,
                            detail=f"当日免费任务次数已用完（每 IP 每日 {MAX_TASKS_PER_IP_DAY} 次）")

    # 建任务（状态先落库）
    task_id = create_task(target, ip, True)
    out_dir = OUTPUT_DIR / task_id
    out_dir.mkdir(parents=True, exist_ok=True)
    _set_state(task_id, "pending", 0, "排队中")
    bump_usage(ip, day)

    # 后台异步执行
    asyncio.create_task(run_pipeline(task_id, target, ip, out_dir))
    return {"task_id": task_id, "status": "pending"}


@app.get("/api/task/{task_id}")
async def task_status(task_id: str):
    """任务进度轮询接口。"""
    state = _TASK_STATE.get(task_id)
    if state is None:
        state = get_web_task(task_id)
    if state is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return state


def _report_dir(task_id: str) -> Path:
    state = _TASK_STATE.get(task_id) or get_web_task(task_id) or {}
    report_dir = state.get("report_dir", "") or str(OUTPUT_DIR / task_id)
    return Path(report_dir)


@app.get("/api/task/{task_id}/report")
async def task_report(task_id: str):
    """在线预览报告（Markdown 文本）。"""
    md_path = _report_dir(task_id) / "report.md"
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="报告尚未生成")
    return JSONResponse({"markdown": md_path.read_text(encoding="utf-8")})


@app.get("/api/task/{task_id}/download")
async def task_download(task_id: str):
    """下载 Markdown 报告。"""
    md_path = _report_dir(task_id) / "report.md"
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="报告尚未生成")
    return FileResponse(md_path, filename=f"sourcetrace-{task_id[:8]}.md",
                        media_type="text/markdown; charset=utf-8")


@app.get("/api/task/{task_id}/interfaces")
async def task_interfaces(task_id: str):
    """接口清单 JSON。"""
    path = _report_dir(task_id) / "interfaces.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="接口清单尚未生成")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.get("/api/task/{task_id}/chains")
async def task_chains(task_id: str):
    """业务链路 JSON。"""
    path = _report_dir(task_id) / "chains.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="业务链路尚未生成")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.get("/api/health")
async def health():
    return {"status": "ok", "time": datetime.now().isoformat(timespec="seconds")}


if __name__ == "__main__":
    import uvicorn

    from config import WEB_HOST, WEB_PORT

    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT)
