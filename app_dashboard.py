"""Dashboard Streamlit : `streamlit run app_dashboard.py`"""
from collections import Counter
from datetime import datetime, timezone

import streamlit as st

from config import DOCUMENTS, SETTINGS
from redteam.guardrails import Mode
from redteam.logging_utils import SecurityLogger
from redteam.rag import RagPipeline, build_retriever, make_llm

st.set_page_config(page_title="Secure Enterprise RAG - AI Red Teaming", page_icon="🛡️", layout="wide")

MODE_LABELS = {
    Mode.VULNERABLE: "Vulnérable (aucune défense)",
    Mode.OUTPUT_ONLY: "Guardrail de sortie seul",
    Mode.FULL: "Défense en profondeur (3 couches)",
}


@st.cache_resource
def get_retriever(doc_key: str):
    return build_retriever(DOCUMENTS[doc_key])


@st.cache_resource
def get_llm():
    return make_llm(SETTINGS)  # température 0 + seed fixe : démo reproductible


@st.cache_resource
def get_logger():
    return SecurityLogger(SETTINGS.logs_dir / "incidents.jsonl")


with st.sidebar:
    st.header("⚙️ Configuration du labo")
    mode = st.radio("Mode de défense", list(Mode), format_func=MODE_LABELS.get, index=2)
    doc_key = st.radio("Corpus RAG", list(DOCUMENTS), format_func=lambda k: {"strict": "Strict (sans fuite)", "piege": "Piégé (injection indirecte)"}[k])
    show_debug = st.checkbox("Afficher sortie brute et contexte (debug Red Team)", value=False)
    if st.button("🗑️ Réinitialiser la session (l'audit reste dans logs/)"):
        st.session_state.messages = []
        st.session_state.session_start = datetime.now(timezone.utc).isoformat(timespec="seconds")  # le fichier d'audit est conservé
        st.rerun()

logger = get_logger()
pipeline = RagPipeline(get_retriever(doc_key), get_llm(), mode, SETTINGS, logger)

st.title("🛡️ Secure Enterprise RAG - AI Red Teaming Dashboard")
st.caption(f"Top 10 OWASP LLM · Modèle local : {SETTINGS.llm_model} (Ollama) · Mode : {MODE_LABELS[mode]}")

left, right = st.columns([2, 1])
st.session_state.setdefault("messages", [])
st.session_state.setdefault("session_start", datetime.now(timezone.utc).isoformat(timespec="seconds"))

with left:
    st.subheader("💬 Chatbot de l'entreprise")
    for m in st.session_state.messages:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m.get("debug") and show_debug:
                st.code(m["debug"])
    if query := st.chat_input("Posez votre question ou testez un prompt d'attaque..."):
        st.session_state.messages.append({"role": "user", "content": query})
        with st.spinner("phi3 réfléchit..."):
            a = pipeline.ask(query)
        debug = f"corpus={doc_key} mode={mode.value} couche={a.layer} règle={a.rule} latence={a.latency_s:.1f}s\nlignes retirées={a.dropped}\nbrut={a.raw}"
        st.session_state.messages.append({"role": "assistant", "content": a.final, "debug": debug})
        st.rerun()

with right:
    st.subheader("📊 Panneau de sécurité (Blue Team)")
    events = [e for e in logger.read() if e["ts"] >= st.session_state.session_start]
    by_layer = Counter(e["layer"] for e in events)
    st.metric("Pare-feu LLM", "ACTIF 🟢" if mode != Mode.VULNERABLE else "INACTIF 🔴")
    c1, c2, c3 = st.columns(3)
    c1.metric("Entrée", by_layer["input"])
    c2.metric("Retrieval", by_layer["retrieval"])
    c3.metric("Sortie", by_layer["output"])
    st.subheader("🚨 Journal d'incidents")
    if not events:
        st.info("Aucun incident enregistré.")
    for e in reversed(events[-8:]):
        st.error(f"**{e['layer']}** · `{e['rule']}` · {e['mode']} · {e['ts'][11:19]}\n\n{e['query']}")
