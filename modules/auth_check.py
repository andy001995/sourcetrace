# modules/auth_check.py
# 阶段1：前置准入校验
#   - 命令行形态：交互式授权确认弹窗（y/N），未确认直接终止任务；
#   - 网页版形态：由前端弹窗勾选承诺后提交 confirmed=True；
#   - 无论哪种形态，都向 SQLite 落一条任务记录（任务ID、目标、时间、IP、确认状态）。
import sqlite3
import uuid
from datetime import datetime

from config import SQLITE_DB_PATH
from utils.logger import logger


def init_db() -> None:
    """初始化数据库：授权记录表 + 网页任务表 + 每IP每日限流计数表。"""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS task_record (
            id         TEXT PRIMARY KEY,          -- 任务ID (uuid)
            target     TEXT NOT NULL,             -- 目标站点
            time       TEXT NOT NULL,             -- 任务创建时间
            client_ip  TEXT,                      -- 发起端 IP（CLI 标记为 CLI）
            confirmed  INTEGER NOT NULL           -- 授权确认状态 1/0
        );
        CREATE TABLE IF NOT EXISTS web_tasks (
            task_id     TEXT PRIMARY KEY,
            status      TEXT DEFAULT 'pending',   -- pending/running/done/failed
            progress    INTEGER DEFAULT 0,
            message     TEXT DEFAULT '',
            report_dir  TEXT DEFAULT '',
            created_at  TEXT,
            updated_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS usage (
            ip  TEXT NOT NULL,
            day TEXT NOT NULL,                    -- YYYY-MM-DD
            cnt INTEGER DEFAULT 0,
            PRIMARY KEY (ip, day)
        );
        """
    )
    conn.commit()
    conn.close()


def create_task(target: str, client_ip: str, confirmed: bool) -> str:
    """写入授权确认记录，返回任务 ID。"""
    task_id = str(uuid.uuid4())
    now = datetime.now().isoformat(timespec="seconds")
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        conn.execute(
            "INSERT INTO task_record (id, target, time, client_ip, confirmed) VALUES (?, ?, ?, ?, ?)",
            (task_id, target, now, client_ip, 1 if confirmed else 0),
        )
        conn.commit()
    finally:
        conn.close()
    logger.info(
        "授权记录已落库 task_id=%s target=%s ip=%s confirmed=%s",
        task_id, target, client_ip, confirmed,
    )
    return task_id


# ============ 网页版任务状态表读写 ============

def upsert_web_task(task_id: str, status: str, progress: int, message: str,
                    report_dir: str = "") -> None:
    """写入/更新网页任务状态（供前端轮询）。"""
    now = datetime.now().isoformat(timespec="seconds")
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        conn.execute(
            """INSERT INTO web_tasks (task_id, status, progress, message, report_dir, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET
                 status=excluded.status, progress=excluded.progress,
                 message=excluded.message, report_dir=excluded.report_dir,
                 updated_at=excluded.updated_at""",
            (task_id, status, progress, message, report_dir, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def get_web_task(task_id: str) -> dict | None:
    """读取网页任务状态。"""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        row = conn.execute(
            "SELECT task_id, status, progress, message, report_dir FROM web_tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {
        "task_id": row[0], "status": row[1], "progress": row[2],
        "message": row[3], "report_dir": row[4],
    }


def bump_usage(ip: str, day: str) -> int:
    """每 IP 每日任务计数 +1，返回当日累计次数。"""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        conn.execute(
            "INSERT INTO usage (ip, day, cnt) VALUES (?, ?, 1) "
            "ON CONFLICT(ip, day) DO UPDATE SET cnt = usage.cnt + 1",
            (ip, day),
        )
        conn.commit()
        cnt = conn.execute(
            "SELECT cnt FROM usage WHERE ip=? AND day=?", (ip, day)
        ).fetchone()[0]
    finally:
        conn.close()
    return cnt


def get_usage(ip: str, day: str) -> int:
    """查询某 IP 当日已用次数。"""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    try:
        row = conn.execute(
            "SELECT cnt FROM usage WHERE ip=? AND day=?", (ip, day)
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


# ============ 命令行授权确认弹窗 ============

def cli_confirm(target: str) -> bool:
    """命令行交互授权确认。返回 True 表示用户已确认授权。"""
    print("=" * 64)
    print("【授权确认弹窗】目标站点：%s" % target)
    print("本工具仅下载该站点公开的静态 HTML/JS/配置文件，")
    print("不对提取到的任何接口发包、不扫描端口、不 Fuzz、不爆破、不做漏洞验证。")
    print("所有接口连通性测试 / 漏洞验证 / 业务伤害判定均由人工完成。")
    print("=" * 64)
    try:
        answer = input("我已获得目标站点【书面授权】，同意继续？(y/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


init_db()
