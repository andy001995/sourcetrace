# utils/scope_classifier.py
import json, os

_CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "oppo_scope.json")

def _load():
    with open(_CFG_PATH, encoding="utf-8") as f:
        return json.load(f)

def _is_package(t):
    return t.startswith("com.") and "/" not in t

def classify(target):
    cfg = _load()
    t = target.lower().strip()
    if t.startswith("http"):
        t = t.split("://", 1)[1].split("/", 1)[0]

    if t in cfg["third_party_exact"]:
        return {"target": target, "ownership": "third_party", "importance": "third_party",
                "environment": "prod", "accepted_severity": "high_critical_only", "confidence": "high"}

    for kw in cfg["third_party_embedded_keywords"]:
        if kw in t:
            return {"target": target, "ownership": "third_party", "importance": "third_party",
                    "environment": "prod", "accepted_severity": "high_critical_only", "confidence": "medium"}

    pkg = _is_package(t)

    is_self = False
    if pkg:
        is_self = any(t.startswith(p) for p in cfg["self_package_prefixes"])
    else:
        is_self = any(t == s or t.endswith("." + s) for s in cfg["self_suffixes"])

    if not is_self:
        return {"target": target, "ownership": "unknown", "importance": "unknown",
                "environment": "unknown", "accepted_severity": "unknown", "confidence": "low"}

    is_test = False
    if not pkg:
        if any(t.endswith(s) for s in cfg["test_suffixes"]):
            is_test = True
        elif any(k in t.split(".")[0] for k in cfg["test_keywords"]):
            is_test = True
    if is_test:
        return {"target": target, "ownership": "self", "importance": "test",
                "environment": "test", "accepted_severity": "all", "confidence": "high"}

    for biz, kws in cfg["core_businesses"].items():
        if any(kw in t for kw in kws):
            return {"target": target, "ownership": "self", "importance": "core",
                    "business": biz, "environment": "prod",
                    "accepted_severity": "all", "confidence": "medium",
                    "note": "keyword heuristic, needs manual confirmation"}

    return {"target": target, "ownership": "self", "importance": "non_core",
            "environment": "prod", "accepted_severity": "all", "confidence": "medium"}

if __name__ == "__main__":
    import sys
    for a in sys.argv[1:]:
        print(json.dumps(classify(a), ensure_ascii=False))
