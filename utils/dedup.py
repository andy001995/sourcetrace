# utils/dedup.py
# 去重工具：
#   1) 接口去重：以 (METHOD, url) 为唯一键，冲突时保留置信度更高的一条，并合并参数与来源。
#   2) 资源 URL 去重：由 collector 的 visited 集合实现（见 collector.py）。
from utils.logger import logger

# 置信度优先级：高（AST 命中） > 中（LLM 推断） > 低（正则兜底）
_CONF_PRIORITY = {"高": 3, "中": 2, "低": 1}


def _merge_params(target: list, source: list) -> None:
    """把 source 中不重复的参数并入 target。"""
    for p in source:
        if p and p not in target:
            target.append(p)


def dedup_interfaces(items: list[dict]) -> list[dict]:
    """接口去重，返回去重后的新列表。"""
    result: dict[tuple, dict] = {}
    for item in items:
        key = (item.get("method", "GET").upper(), item.get("url", ""))
        params = item.get("params") or []
        sources = item.get("source_files") or []
        if item.get("source_file"):
            if item["source_file"] not in sources:
                sources.append(item["source_file"])
        conf = _CONF_PRIORITY.get(item.get("confidence", "低"), 1)

        if key not in result:
            item["params"] = list(params)
            item["source_files"] = sources
            result[key] = item
            continue

        prev = result[key]
        prev_conf = _CONF_PRIORITY.get(prev.get("confidence", "低"), 1)
        if conf > prev_conf:
            # 新条目置信度更高：以新条目为准，但合并旧条目的来源与参数
            item["params"] = list(params)
            merged_sources = list(sources)
            for s in prev.get("source_files") or []:
                if s not in merged_sources:
                    merged_sources.append(s)
            item["source_files"] = merged_sources
            result[key] = item
        else:
            # 保留旧条目，并入新条目的参数与来源
            _merge_params(prev.setdefault("params", []), params)
            for s in sources:
                if s not in prev.setdefault("source_files", []):
                    prev["source_files"].append(s)

    out = list(result.values())
    logger.info("接口去重完成：%d -> %d", len(items), len(out))
    return out
