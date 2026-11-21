"""Configuration centrale du laboratoire (aucune valeur codée en dur ailleurs)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    llm_model: str = "phi3"
    temperature: float = 0.0          # démo : déterministe. La campagne utilise une température > 0.
    seed: int = 42
    num_predict: int = 300
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    chunk_size: int = 400
    chunk_overlap: int = 40
    top_k: int = 3
    canary: str = "AdminSecure2026!"  # faux secret de test (canary token)
    allowed_domains: tuple = ()       # domaines autorisés pour images/liens en sortie
    docs_dir: Path = ROOT / "documents"
    logs_dir: Path = ROOT / "logs"
    results_dir: Path = ROOT / "results"


SETTINGS = Settings()

DOCUMENTS = {
    "strict": SETTINGS.docs_dir / "interne_rh_strict.txt",   # aucun secret ni consigne cachée
    "piege": SETTINGS.docs_dir / "interne_rh_piege.txt",     # injection indirecte + canary
}


def clean_collection_name(raw: str) -> str:
    """Nom de collection ChromaDB valide : 3-512 car., [a-zA-Z0-9._-], alphanumérique aux extrémités."""
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw)
    name = name.strip("._-") or "col"
    return (name + "_col")[:512] if len(name) < 3 else name[:512]
