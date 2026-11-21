"""Lecture et agrégation des CSV de campagne (utilisé par la page Statistiques)."""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from redteam.evaluator import judge_utility, wilson
from redteam.payloads import BENIGN
from redteam.payloads_heldout import BENIGN_HELDOUT

MODE_ORDER = ["vulnerable", "output_only", "defense_in_depth"]
BOOL_COLS = ("raw_leak", "delivered_leak", "exfil_channel", "useful", "blocked")
EXPECT = {p.id: p.expect for p in BENIGN + BENIGN_HELDOUT}


def load_rows(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for c in BOOL_COLS:
            r[c] = r[c] == "True"
        r["latency_s"] = float(r["latency_s"])
    return rows


def useful_now(r: dict) -> bool:
    """Réponse non bloquée, sans fuite, avec un mot-clé attendu (catalogue actuel)."""
    return (not r["blocked"] and not r["delivered_leak"]
            and judge_utility(r["final"], EXPECT.get(r["payload"], "")))


def _ci(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"rate": k / n if n else 0.0, "ci95_low": lo, "ci95_high": hi}


def asr_by_category(rows: list[dict]) -> list[dict]:
    acc = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        if r["kind"] == "attack":
            a = acc[(r["mode"], r["category"])]
            a[0] += 1; a[1] += r["raw_leak"]; a[2] += r["delivered_leak"]
    out = []
    for (mode, cat), (n, raw, dlv) in acc.items():
        c = _ci(dlv, n)
        out.append({"mode": mode, "category": cat, "n": n, "raw_asr": raw / n,
                    "asr": c["rate"], "ci95_low": c["ci95_low"], "ci95_high": c["ci95_high"]})
    return sorted(out, key=lambda d: (MODE_ORDER.index(d["mode"]), d["category"]))


def asr_overall(rows: list[dict]) -> list[dict]:
    acc = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["kind"] == "attack":
            a = acc[r["mode"]]
            a[0] += 1; a[1] += r["delivered_leak"]
    out = []
    for mode in MODE_ORDER:
        if mode in acc:
            n, k = acc[mode]
            out.append({"mode": mode, "n": n, "successes": k, **_ci(k, n)})
    return out


def benign_by_mode(rows: list[dict]) -> list[dict]:
    acc = defaultdict(lambda: [0, 0, 0, 0])
    for r in rows:
        if r["kind"] == "benign":
            a = acc[r["mode"]]
            a[0] += 1; a[1] += r["blocked"]; a[2] += useful_now(r); a[3] += r["delivered_leak"]
    out = []
    for mode in MODE_ORDER:
        if mode in acc:
            n, blk, use, leak = acc[mode]
            u = _ci(use, n)
            out.append({"mode": mode, "n": n, "blocked": blk, "fpr": blk / n,
                        "utility": u["rate"], "utility_ci95_low": u["ci95_low"],
                        "utility_ci95_high": u["ci95_high"], "leaked_to_legit_user": leak})
    return out


def leak_by_payload(rows: list[dict], mode: str = "vulnerable") -> list[dict]:
    acc = defaultdict(lambda: [0, 0, ""])
    for r in rows:
        if r["kind"] == "attack" and r["mode"] == mode:
            a = acc[r["payload"]]
            a[0] += 1; a[1] += r["delivered_leak"]; a[2] = r["category"]
    return [{"payload": p, "category": c, "n": n, "leaks": k, "rate": k / n}
            for p, (n, k, c) in sorted(acc.items())]


def blocks_by_layer(rows: list[dict]) -> list[dict]:
    acc = defaultdict(int)
    for r in rows:
        if r["blocked"]:
            acc[(r["mode"], r["kind"], r["layer"], r["rule"])] += 1
    return [{"mode": m, "kind": k, "layer": l, "rule": rule, "count": n}
            for (m, k, l, rule), n in sorted(acc.items())]