"""Run every case in a module (or all modules) and compute attack success rate."""

from __future__ import annotations

import config
from lab.modules import MODULES


def run_case(module, case: dict, secure: bool, model: str) -> dict:
    try:
        res = module.run(case, secure=secure, model=model)
    except Exception as e:  # keep the batch going if one case errors
        return {"output": f"ERROR: {e}", "success": False, "trace": [f"exception: {e}"]}
    res["id"] = case["id"]
    res["title"] = case["title"]
    res["benign"] = case.get("benign", False)
    return res


def run_module(module, secure: bool, model: str) -> dict:
    results = [run_case(module, c, secure, model) for c in module.CASES]
    attacks = [r for r in results if not r["benign"]]
    asr = sum(r["success"] for r in attacks) / len(attacks) if attacks else 0.0
    return {"module": module.NAME, "owasp": module.OWASP, "secure": secure, "asr": asr, "results": results}


def run_all(model: str | None = None) -> list[dict]:
    model = model or config.DEFAULT_MODEL
    out = []
    for m in MODULES:
        for secure in (False, True):
            out.append(run_module(m, secure, model))
    return out
