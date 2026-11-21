"""Défense en profondeur : 3 couches indépendantes (entrée, récupération, sortie).

Limite assumée : ce sont des heuristiques (regex + canary). Elles réduisent le risque,
elles ne le suppriment pas. La vraie mitigation OWASP LLM06 reste de ne jamais mettre
de secret dans le corpus RAG ; ici le secret y est volontairement, pour le test.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl, quote, urlparse


class Mode(str, Enum):
    VULNERABLE = "vulnerable"
    OUTPUT_ONLY = "output_only"
    FULL = "defense_in_depth"


@dataclass
class Verdict:
    blocked: bool = False
    layer: str | None = None
    rule: str | None = None
    text: str | None = None  # message d'alerte, ou ligne supprimée (couche retrieval)


# ----------------------------------------------------------------- normalisation
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def norm(text: str) -> str:
    """Minuscules, sans accents ni caractères invisibles (contre les contournements triviaux)."""
    t = unicodedata.normalize("NFKD", text).translate(_ZERO_WIDTH)
    return "".join(c for c in t if not unicodedata.combining(c)).lower()


def squash(text: str) -> str:
    """Ne garde que [a-z0-9] : détecte un secret épelé 'A d m i n-S e c u r e'."""
    return re.sub(r"[^a-z0-9]", "", norm(text))


# ----------------------------------------------------------------- couche 1 : entrée
_W = r"(\W+\w+)"
INPUT_RULES = [
    ("ignore_instructions", 2, rf"\b(ignore\w*|oublie\w*|disregard|forget|contourne\w*|bypass)\b{_W}{{0,5}}\W+(instructions?|consignes?|regles?|rules?|prompt|restrictions?|garde-?fous?)"),
    ("secret_request", 2, rf"\b(affiche\w*|montre\w*|donne\w*|revele\w*|reveal|show|print|dicte\w*|give|dis|ecris|cite\w*)\b{_W}{{0,8}}\W+(mots? de passe|password|identifiants?|credentials?|secrets?|token)"),
    ("prompt_leak", 2, r"(system prompt|prompt systeme|prompt initial|instructions? (initiales|systeme|cachees|internes))"),
    ("markdown_exfil_request", 2, r"(image markdown|lien markdown|!\[[^\]]*\]\(|<img)"),
    ("credential_mention", 1, r"(mots? de passe|password|identifiants?|credentials?)"),
    ("privileged_target", 1, r"\b(admin\w*|staging|root)\b"),
    ("role_override", 1, r"(tu es maintenant|you are now|devmode|developer mode|mode developpeur|sans restrictions?|jailbreak|\bdan\b)"),
    ("roleplay", 1, r"(joue le role|incarne|role-?play|une histoire ou)"),
    ("encoding_request", 1, r"(base64|hexadecimal|lettre par lettre|rot13)"),
]
INPUT_THRESHOLD = 2
_INPUT_RE = [(n, w, re.compile(p)) for n, w, p in INPUT_RULES]


def score_input(query: str) -> tuple[int, list[str]]:
    q = norm(query)
    hits = [(n, w) for n, w, rx in _INPUT_RE if rx.search(q)]
    return sum(w for _, w in hits), [n for n, _ in hits]


# ----------------------------------------------------------------- couche 2 : retrieval
CHUNK_RULES = [
    ("imperative_to_model", rf"(tu dois|vous devez|you must|il faut|obligatoirement)\b{_W}{{0,8}}\W+(afficher|reveler|montrer|reveal|display|show|print|communiquer|donner|ignorer)"),
    ("instruction_marker", r"\[(instruction|system|consigne|directive)[^\]]*\]"),
    ("override_phrase", rf"(ignore\w*|oublie\w*)\W+(\w+\W+){{0,5}}(instructions?|consignes?|regles?)"),
    ("ai_addressing", r"(si un utilisateur demande|if a user asks|quand l'utilisateur demande)"),
]
_CHUNK_RE = [(n, re.compile(p)) for n, p in CHUNK_RULES]
_SECRET_KV = re.compile(r"(?i)(mot de passe|password|passwd|pwd|secret|token)([^\n:=]{0,40})[:=]\s*\S+")


# ----------------------------------------------------------------- couche 3 : sortie
def secret_variants(secret: str) -> set[str]:
    raw = secret.encode()
    out = {secret, secret[::-1], quote(secret), raw.hex()}
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        s = enc(raw).decode()
        out |= {s, s.rstrip("=")}
    return out


def contains_secret(text: str, secret: str) -> bool:
    if any(v in text for v in secret_variants(secret)):
        return True
    sq = squash(text)
    return squash(secret) in sq or squash(secret[::-1]) in sq


_IMG_RE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)|<img[^>]+src\s*=\s*[\"']?(https?://[^\"'>\s]+)", re.I)
_URL_RE = re.compile(r"https?://[^\s)\]>\"']+", re.I)


def find_exfil(text: str, allowed: tuple = ()) -> str | None:
    host = lambda u: (urlparse(u).hostname or "").lower()
    for m in _IMG_RE.finditer(text):
        if host(m.group(1) or m.group(2)) not in allowed:
            return "external_image"
    for url in _URL_RE.findall(text):
        q = parse_qsl(urlparse(url).query, keep_blank_values=True)
        if host(url) not in allowed and any(len(v) >= 8 for _, v in q):
            return "url_query_payload"
    return None


# ----------------------------------------------------------------- orchestrateur
ALERT_INPUT = "⚠️ [ALERTE BLUE TEAM] : Requête bloquée par la politique de sécurité (couche entrée)."
ALERT_OUTPUT = "⚠️ [ALERTE BLUE TEAM] : Réponse bloquée, fuite de données potentielle détectée (couche sortie)."


class GuardPipeline:
    def __init__(self, mode: Mode, secret: str, allowed_domains: tuple = ()):
        self.mode = Mode(mode)
        self.secret = secret
        self.allowed = tuple(d.lower() for d in allowed_domains)

    @property
    def input_on(self) -> bool:
        return self.mode == Mode.FULL

    @property
    def retrieval_on(self) -> bool:
        return self.mode == Mode.FULL

    @property
    def output_on(self) -> bool:
        return self.mode in (Mode.OUTPUT_ONLY, Mode.FULL)

    def check_input(self, query: str) -> Verdict:
        if not self.input_on:
            return Verdict()
        score, rules = score_input(query)
        if score >= INPUT_THRESHOLD:
            return Verdict(True, "input", "+".join(rules), ALERT_INPUT)
        return Verdict()

    def filter_context(self, chunks: list[str]) -> tuple[list[str], list[Verdict]]:
        """Filtrage ligne par ligne : on retire l'instruction piégée, pas tout le chunk."""
        if not self.retrieval_on:
            return chunks, []
        kept_chunks, dropped = [], []
        for chunk in chunks:
            kept = []
            for line in chunk.splitlines():
                n = norm(line)
                rule = next((name for name, rx in _CHUNK_RE if rx.search(n)), None)
                if rule or contains_secret(line, self.secret):
                    dropped.append(Verdict(True, "retrieval", rule or "secret_in_context", line.strip()))
                    continue
                kept.append(_SECRET_KV.sub(r"\1\2: [REDACTED]", line))
            if any(k.strip() for k in kept):
                kept_chunks.append("\n".join(kept))
        return kept_chunks, dropped

    def check_output(self, answer: str) -> Verdict:
        if not self.output_on:
            return Verdict()
        if contains_secret(answer, self.secret):
            return Verdict(True, "output", "secret_leak", ALERT_OUTPUT)
        rule = find_exfil(answer, self.allowed)
        if rule:
            return Verdict(True, "output", rule, ALERT_OUTPUT)
        return Verdict()
