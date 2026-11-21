"""Page Statistiques : lit les CSV de results/ et affiche les mesures de la campagne."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import altair as alt
import pandas as pd
import streamlit as st

from config import SETTINGS
from redteam import report as rp

st.set_page_config(page_title="Statistiques Red Team", page_icon="📊", layout="wide")
st.title("📊 Statistiques de la campagne Red Team")

LABELS = {"vulnerable": "Vulnérable", "output_only": "Sortie seule", "defense_in_depth": "Défense en profondeur"}
COLORS = alt.Scale(domain=list(LABELS.values()), range=["#d62728", "#ff9f1c", "#2a9d8f"])

files = sorted(SETTINGS.results_dir.glob("campaign_*_raw.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
if not files:
    st.info("Aucun résultat dans results/. Lance d'abord : python run_campaign.py --trials 5 --scenarios piege")
    st.stop()

path = st.sidebar.selectbox("Fichier de résultats", files, format_func=lambda p: p.name)
rows = rp.load_rows(path)
st.sidebar.caption(f"{len(rows)} lignes · jeu : {'held-out' if 'heldout' in path.name else 'principal'}")


def lab(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["mode"] = df["mode"].map(LABELS)
    return df


# ---- 1. indicateurs
st.subheader("1. Taux de réussite des attaques (ASR livré, tous types confondus)")
overall = rp.asr_overall(rows)
cols = st.columns(len(overall))
for col, o in zip(cols, overall):
    col.metric(LABELS[o["mode"]], f"{o['rate']:.0%}",
               help=f"{o['successes']} fuites sur {o['n']} attaques · IC95 [{o['ci95_low']:.0%}, {o['ci95_high']:.0%}]")
    col.caption(f"IC95 [{o['ci95_low']:.0%}, {o['ci95_high']:.0%}] · n={o['n']}")

# ---- 2. ASR par catégorie
st.subheader("2. ASR par catégorie d'attaque et par mode")
df = lab(pd.DataFrame(rp.asr_by_category(rows)))
base = alt.Chart(df).encode(x=alt.X("category:N", title=None), xOffset="mode:N",
                            color=alt.Color("mode:N", scale=COLORS, title="Mode"))
bars = base.mark_bar().encode(y=alt.Y("asr:Q", title="ASR livré", axis=alt.Axis(format="%"),
                                      scale=alt.Scale(domain=[0, 1])),
                              tooltip=["mode", "category", "n", alt.Tooltip("asr:Q", format=".0%"),
                                       alt.Tooltip("ci95_low:Q", format=".0%"), alt.Tooltip("ci95_high:Q", format=".0%")])
ci = base.mark_rule(color="black").encode(y="ci95_low:Q", y2="ci95_high:Q")
st.altair_chart(bars + ci, width="stretch")
st.caption("Barres noires : intervalle de confiance à 95 % (Wilson). Un « 0 % » avec peu d'essais signifie « moins que la borne haute », jamais « zéro ».")

# ---- 3. fuite brute vs livrée
with st.expander("ASR brut (le modèle fuit) contre ASR livré (la victime reçoit)"):
    t = df[["mode", "category", "n", "raw_asr", "asr"]].rename(columns={"raw_asr": "ASR brut", "asr": "ASR livré"})
    st.dataframe(t.style.format({"ASR brut": "{:.0%}", "ASR livré": "{:.0%}"}), width="stretch", hide_index=True)

# ---- 4. par payload
st.subheader("3. Efficacité de chaque attaque contre le modèle sans défense")
pp = pd.DataFrame(rp.leak_by_payload(rows, "vulnerable"))
if not pp.empty:
    ch = alt.Chart(pp).mark_bar().encode(
        y=alt.Y("payload:N", sort="-x", title=None),
        x=alt.X("rate:Q", title="Taux de fuite", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
        color=alt.Color("category:N", title="Catégorie"),
        tooltip=["payload", "category", "leaks", "n", alt.Tooltip("rate:Q", format=".0%")])
    st.altair_chart(ch, width="stretch")

# ---- 5. blocages
st.subheader("4. Quelle couche a bloqué quoi ?")
bl = pd.DataFrame(rp.blocks_by_layer(rows))
if bl.empty:
    st.write("Aucun blocage dans ce fichier.")
else:
    bl["mode"] = bl["mode"].map(LABELS)
    bl["kind"] = bl["kind"].map({"attack": "attaque", "benign": "requête légitime"})
    st.dataframe(bl.rename(columns={"kind": "type", "layer": "couche", "rule": "règle", "count": "nombre"}),
                 width="stretch", hide_index=True)

# ---- 6. requêtes légitimes
st.subheader("5. Impact sur les utilisateurs légitimes")
bn = lab(pd.DataFrame(rp.benign_by_mode(rows)))
bn["Utilité (IC95)"] = bn.apply(lambda r: f"{r.utility:.0%} [{r.utility_ci95_low:.0%}, {r.utility_ci95_high:.0%}]", axis=1)
st.dataframe(bn[["mode", "n", "blocked", "fpr", "Utilité (IC95)", "leaked_to_legit_user"]].rename(columns={
    "mode": "Mode", "n": "Requêtes", "blocked": "Bloquées", "fpr": "Taux de blocage",
    "leaked_to_legit_user": "Ayant reçu le secret"}).style.format({"Taux de blocage": "{:.0%}"}),
    width="stretch", hide_index=True)
st.caption("Utilité = réponse non bloquée, contenant un mot-clé attendu et sans fuite du secret.")

# ---- 7. journal live
st.subheader("6. Journal d'incidents du dashboard (temps réel)")
log = SETTINGS.logs_dir / "incidents.jsonl"
if log.exists():
    ev = pd.read_json(log, lines=True)
    if not ev.empty:
        st.bar_chart(ev.groupby(["layer", "mode"]).size().unstack(fill_value=0))
        st.dataframe(ev.tail(20).iloc[::-1], width="stretch", hide_index=True)
else:
    st.caption("Aucun incident enregistré par le dashboard pour l'instant.")