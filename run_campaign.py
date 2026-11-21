"""Lance la campagne Red Team. Prérequis : `ollama serve` + `ollama pull phi3`.

    python run_campaign.py --trials 10 --scenarios piege            # jeu principal
    python run_campaign.py --trials 5  --scenarios piege --set heldout   # jeu held-out (ne pas tuner dessus)

Les résultats sont sauvegardés après CHAQUE essai : une interruption (Ctrl+C, veille) ne perd rien.
"""
import argparse
from datetime import datetime

from config import DOCUMENTS, SETTINGS
from redteam.evaluator import run_campaign, save, summarize
from redteam.guardrails import Mode
from redteam.payloads import ATTACKS, BENIGN
from redteam.payloads_heldout import ATTACKS_HELDOUT, BENIGN_HELDOUT
from redteam.rag import build_retriever, make_llm

SETS = {"main": (ATTACKS, BENIGN), "heldout": (ATTACKS_HELDOUT, BENIGN_HELDOUT)}


def print_report(summary: dict) -> None:
    print("\n=== ASR (après guardrails) — IC 95 % de Wilson ===")
    print(f"{'scénario':8} {'mode':18} {'catégorie':20} {'n':>3} {'ASR brut':>9} {'ASR livré':>10}  IC95")
    for r in summary["asr"]:
        print(f"{r['scenario']:8} {r['mode']:18} {r['category']:20} {r['n']:>3} "
              f"{r['raw_asr']:>8.0%} {r['asr']:>10.0%}  [{r['ci95_low']:.0%}, {r['ci95_high']:.0%}]")
    print("\n=== Requêtes légitimes : blocages (FPR) et utilité (réponse correcte) ===")
    for r in summary["false_positives"]:
        print(f"{r['scenario']:8} {r['mode']:18} n={r['n']:>3}  FPR={r['fpr']:.0%}  utilité={r['utility']:.0%} "
              f"[{r['utility_ci95_low']:.0%}, {r['utility_ci95_high']:.0%}]")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--seed", type=int, default=1000)
    ap.add_argument("--set", dest="payload_set", choices=list(SETS), default="main")
    ap.add_argument("--scenarios", nargs="+", default=list(DOCUMENTS), choices=list(DOCUMENTS))
    args = ap.parse_args()

    attacks, benign = SETS[args.payload_set]
    tag = datetime.now().strftime(f"campaign_{args.payload_set}_%Y%m%d_%H%M%S")
    holder: dict = {"rows": []}

    def checkpoint(rows: list[dict]) -> None:
        holder["rows"] = list(rows)
        save(rows, summarize(rows), SETTINGS.results_dir, tag)

    retrievers = {name: build_retriever(DOCUMENTS[name]) for name in args.scenarios}
    try:
        run_campaign(
            retrievers, attacks, benign, list(Mode),
            llm_factory=lambda temp, seed: make_llm(SETTINGS, temp, seed),
            trials=args.trials, temperature=args.temperature, base_seed=args.seed,
            progress=print, checkpoint=checkpoint,
        )
    except KeyboardInterrupt:
        print("\nInterrompu : résultats partiels conservés.")

    if holder["rows"]:
        print(f"\n[jeu : {args.payload_set}]")
        print_report(summarize(holder["rows"]))
        print(f"\nFichiers : {SETTINGS.results_dir / (tag + '_raw.csv')}\n           {SETTINGS.results_dir / (tag + '_summary.json')}")


if __name__ == "__main__":
    main()
