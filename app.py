"""AI Security Lab -- a UI to expose and then fix LLM/agent vulnerabilities.

Run:  streamlit run app.py
Each module runs the same attack in Vulnerable mode and Secure mode so you can compare.
All tools are mocked and all attack goals are harmless (a canary string or a fake fact).
"""

import streamlit as st

import config
from lab.harness import run_case
from lab.modules import MODULES

st.set_page_config(page_title="AI Security Lab", layout="wide")
st.title("🛡️ AI Security Lab")
st.caption("Expose LLM/agent vulnerabilities, then flip each defense on. Mock tools only; harmless canary-based goals.")

with st.sidebar:
    st.header("Settings")
    model = st.selectbox("Model", config.MODELS, index=config.MODELS.index(config.DEMO_MODEL))
    st.caption(f"Profile `{config.PROFILE_NAME}` · region `{config.REGION}`")
    st.info(
        "Whether an attack lands depends on **both** the missing app-layer defense and the "
        "model's own training. Strong models (Sonnet/Opus 5.x) resist many attacks unaided, so "
        "the vulnerable lane looks empty. **Haiku 4.5** (default here) lets more attacks land so "
        "you can watch Secure mode block them. The model is never your security boundary.",
        icon="💡",
    )
    st.divider()
    st.markdown("**Legend**")
    st.markdown("🔴 attack succeeded 🟢 attack blocked ⚪ benign control")

names = [m.NAME for m in MODULES]
tabs = st.tabs(names)

for tab, module in zip(tabs, MODULES):
    with tab:
        st.subheader(module.NAME)
        st.caption(f"OWASP: {module.OWASP}")
        st.write(module.DESCRIPTION)
        c1, c2 = st.columns(2)
        c1.warning(f"**Vulnerable mode:** {module.VULN_NOTE}")
        c2.success(f"**Secure mode:** {module.FIX_NOTE}")

        mode = st.radio("Mode", ["Vulnerable", "Secure", "Compare both"], horizontal=True, key=f"mode_{module.NAME}")
        case_titles = [f"{c['id']} — {c['title']}" for c in module.CASES]
        picked = st.multiselect("Test cases", case_titles, default=case_titles, key=f"cases_{module.NAME}")
        chosen = [c for c, t in zip(module.CASES, case_titles) if t in picked]

        if st.button("Run", key=f"run_{module.NAME}", type="primary"):
            modes = [("Vulnerable", False), ("Secure", True)] if mode == "Compare both" else \
                    [(mode, mode == "Secure")]
            cols = st.columns(len(modes))
            for col, (label, secure) in zip(cols, modes):
                with col:
                    st.markdown(f"### {label}")
                    attacks = total = 0
                    for case in chosen:
                        with st.spinner(f"{case['id']}…"):
                            r = run_case(module, case, secure, model)
                        benign = case.get("benign", False)
                        icon = "⚪" if benign else ("🔴" if r["success"] else "🟢")
                        if not benign:
                            total += 1
                            attacks += int(r["success"])
                        with st.expander(f"{icon} {case['id']} — {case['title']}", expanded=not benign):
                            st.markdown("**Model output**")
                            st.code(r["output"] or "(empty)", language=None)
                            st.markdown("**Trace**")
                            st.code("\n".join(r.get("trace", [])) or "(none)", language=None)
                    if total:
                        st.metric("Attack success rate", f"{attacks}/{total}  ({attacks/total:.0%})")
