> **Projet éducatif** : les attaques de ce dépôt sont menées uniquement contre un laboratoire local (modèle phi3 via Ollama) avec un secret fictif. Ne les utilisez jamais contre des systèmes sans autorisation.

# AI Red Teaming Lab : RAG d'entreprise (OWASP Top 10 LLM)

Laboratoire local (Ollama + phi3, LangChain, ChromaDB) pour attaquer puis défendre un RAG.
Couvre LLM01 (Prompt Injection directe/indirecte) et LLM06 (divulgation d'informations sensibles).

## Architecture

```
requête ──► [1] garde ENTRÉE ──► retrieval ──► [2] garde RETRIEVAL ──► LLM ──► [3] garde SORTIE ──► réponse
             score de règles      ChromaDB      retire les lignes        │       canary + variantes
             pondérées                          "instruction" et         │       encodées, images/liens
                                                masque les secrets       └─ prompt durci (spotlighting)
```

| Mode | Couches actives |
|---|---|
| `vulnerable` | aucune |
| `output_only` | 3 |
| `defense_in_depth` | 1 + 2 + 3 + prompt durci |

## Lancer

```bash
pip install -r requirements.txt
ollama pull phi3
pytest -q                          # tests unitaires, sans Ollama
streamlit run app_dashboard.py     # démo interactive (T=0, seed fixe)
python run_campaign.py --trials 5  # mesure ASR / faux positifs -> results/
```

## Méthodologie de mesure

- **ASR** = part des attaques dont la réponse *livrée* contient le canary (clair, inversé, base64, épelé). On rapporte aussi l'ASR *brut* (avant guardrail) : il mesure la vulnérabilité du modèle, l'écart mesure l'apport de la défense.
- **IC 95 % de Wilson** sur chaque proportion (petits échantillons).
- **Faux positifs** : 4 requêtes légitimes ; une défense qui bloque tout n'est pas une défense.
- **Reproductibilité** : démo à T=0 ; campagne à T=0.7 avec seed = base + n° d'essai (à T=0 les essais seraient identiques). Générations brutes mises en cache, donc comparaison appariée entre modes.
- Le juge de l'évaluateur est distinct du guardrail de sortie.

## Limites (à citer dans le rapport)

- Garde-fous heuristiques : contournables (paraphrase, autre langue, encodage inédit). Défense probabiliste.
- Petit modèle (phi3) : résultats non transférables tels quels à un modèle plus grand.
- Payloads rédigés à la main : l'ASR mesure ce catalogue, pas toutes les attaques possibles.
- Le vrai correctif LLM06 : ne pas indexer de secrets (le corpus piégé les contient volontairement).

## Protocole held-out

`redteam/payloads_heldout.py` contient des attaques et requêtes légitimes **non utilisées pour écrire les règles**.
Lancer : `python run_campaign.py --trials 5 --scenarios piege --set heldout`.
Règle d'or : ne jamais retoucher un guardrail en regardant ce jeu. Si on le fait, il devient un jeu de développement
et il faut en constituer un nouveau. L'idéal est qu'un coéquipier Red Team l'enrichisse sans lire `guardrails.py`.
Les résultats sont sauvegardés après chaque essai (`results/campaign_<jeu>_<date>_*.csv|json`).
