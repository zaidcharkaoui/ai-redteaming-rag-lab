"""Inspecte un CSV de campagne (le juge d'utilité est recalculé avec le catalogue actuel).

    python inspect_results.py                       # fichier results/campaign_*_raw.csv le plus récent
    python inspect_results.py results\\campaign_heldout_xxx_raw.csv
"""
import csv
import glob
import sys
from collections import Counter, defaultdict
from pathlib import Path

from redteam.evaluator import judge_utility, wilson
from redteam.payloads import BENIGN
from redteam.payloads_heldout import BENIGN_HELDOUT

EXPECT = {p.id: p.expect for p in BENIGN + BENIGN_HELDOUT}


def latest() -> str:
    files = sorted(glob.glob("results/campaign_*_raw.csv"), key=lambda p: Path(p).stat().st_mtime)
    if not files:
        sys.exit("Aucun fichier results/campaign_*_raw.csv trouvé (vérifie avec : dir results).")
    return files[-1]


def useful_now(r: dict) -> bool:
    """Réponse non bloquée, sans fuite, contenant un mot-clé attendu (catalogue actuel)."""
    return (r["blocked"] == "False" and r["delivered_leak"] == "False"
            and judge_utility(r["final"], EXPECT.get(r["payload"], "")))


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else latest()
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    benign = [r for r in rows if r["kind"] == "benign"]
    attacks = [r for r in rows if r["kind"] == "attack"]
    print(f"Fichier : {path}  ({len(rows)} lignes)\n")

    print("--- 1. Requêtes légitimes BLOQUÉES (faux positifs) ---")
    c = Counter((r["payload"], r["mode"], r["layer"], r["rule"]) for r in benign if r["blocked"] == "True")
    for (p, m, layer, rule), n in sorted(c.items()):
        print(f"  {p:5} {m:17} couche={layer:9} règle={rule}  x{n}")
    if not c:
        print("  aucune")

    print("\n--- 2. Requêtes légitimes NON bloquées et SANS réponse utile ---")
    bad = [r for r in benign if r["blocked"] == "False" and not useful_now(r)]
    c = Counter((r["payload"], r["mode"], "FUITE DU SECRET" if r["delivered_leak"] == "True" else "mot-clé absent",
                 r["final"][:130].replace("\n", " ")) for r in bad)
    for (p, m, why, txt), n in sorted(c.items()):
        print(f"  {p:5} {m:17} [{why}] x{n}\n      > {txt}")
    if not c:
        print("  aucune")

    print("\n--- 3. Fuites ayant atteint l'utilisateur, requêtes d'ATTAQUE ---")
    c = Counter((r["mode"], r["payload"]) for r in attacks if r["delivered_leak"] == "True")
    for (m, p), n in sorted(c.items()):
        print(f"  {m:17} {p:5} x{n}")
    if not c:
        print("  aucune")

    print("\n--- 3b. Taux de fuite par payload, mode vulnerable ---")
    per = defaultdict(lambda: [0, 0, ""])
    for r in attacks:
        if r["mode"] == "vulnerable":
            e = per[r["payload"]]
            e[0] += 1; e[1] += r["delivered_leak"] == "True"; e[2] = r["category"]
    for p, (n, k, cat) in sorted(per.items()):
        print(f"  {p:5} {cat:20} {k:>2}/{n:<2} = {k / n:4.0%}")

    print("\n--- 4. Attaques bloquées, par mode / couche / règle ---")
    c = Counter((r["mode"], r["layer"], r["rule"]) for r in attacks if r["blocked"] == "True")
    for (m, layer, rule), n in sorted(c.items()):
        print(f"  {m:17} {layer:9} {rule:45} x{n}")

    print("\n--- 5. Requêtes LÉGITIMES ayant reçu le secret (fuite sans attaque) ---")
    c = Counter((r["mode"], r["payload"]) for r in benign if r["delivered_leak"] == "True")
    for (m, p), n in sorted(c.items()):
        print(f"  {m:17} {p:5} x{n}")
    if not c:
        print("  aucune")

    print("\n--- 6. Utilité recalculée (correcte, non bloquée, sans fuite) ---")
    by = defaultdict(lambda: [0, 0])
    for r in benign:
        by[r["mode"]][0] += 1
        by[r["mode"]][1] += useful_now(r)
    for m, (n, k) in sorted(by.items()):
        lo, hi = wilson(k, n)
        print(f"  {m:17} {k}/{n} = {k / n:4.0%}  IC95 [{lo:.0%}, {hi:.0%}]")


if __name__ == "__main__":
    main()