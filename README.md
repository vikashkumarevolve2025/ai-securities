# AI Security Lab

A hands-on lab to **expose** LLM / agent vulnerabilities and then **fix** them with a toggle, all
from a Streamlit UI. Every module runs the same attack in **Vulnerable** mode and **Secure** mode so
you can compare. All tools are mocked and every attack goal is harmless — a canary string
(`CANARY-...`) or a fake fact — so success can be scored automatically.

> For authorized testing and learning only, against this lab. Nothing here sends real email or makes
> real network calls.

## Setup

```bash
pip install -r requirements.txt
```

Bedrock access is read from `config.py` (AWS profile `foresight`, region `us-east-1`). Edit that file
to change the profile, region, model list or default.

## Run

```bash
streamlit run app.py
```

Pick a module tab, choose **Vulnerable / Secure / Compare both**, select test cases, and click **Run**.
The UI shows each model output, a trace of what the defense did, and the **attack success rate (ASR)**.

## Modules

| Module | OWASP LLM | Attack it demonstrates | The fix it toggles on |
|---|---|---|---|
| Direct prompt injection | LLM01, LLM07 | Override instructions; leak the system prompt | Instruction hierarchy, input scan, canary redaction |
| Indirect prompt injection | LLM01 | Instructions hidden in a document the model reads | Spotlighting, data/instruction separation, output DLP |
| RAG / knowledge poisoning | LLM04, LLM08 | Poisoned docs steer answers; cross-tenant leak | Source trust, ingestion scan, tenant ACL at query time |
| Agent memory poisoning | LLM01 | A planted instruction persists across sessions | Scan + quarantine memory writes |
| MCP tool poisoning | LLM01, supply chain | Hidden instructions in a tool description; rug pull | Manifest pinning by hash, description scan |
| Agent authorization | LLM06 | Confused deputy: act beyond the user's rights | Policy engine enforced in the tool layer |
| Data-leak prevention | LLM02 | Exfiltrate a secret via a tool/URL | Egress allow-list, output DLP |

## A note on results

Whether an attack lands depends on **both** the missing app-layer defense and the model's own
training. Strong models (Sonnet / Opus 5.x) resist many of these unaided, so the vulnerable lane can
look empty. **Haiku 4.5** is the default demo model because it lets more attacks land, so you can
watch Secure mode block them. The lesson: **the model is never your security boundary** — the app
controls are. This variability is why AI red teaming reports an *attack success rate*, not pass/fail.

## Layout

```
config.py            profile, region, models
app.py               Streamlit UI
lab/llm.py           Bedrock Converse wrapper + tool-calling agent loop
lab/defenses.py      shared defenses (injection scan, spotlighting, DLP, manifest hashing)
lab/rag.py           tiny in-memory TF-IDF RAG store
lab/harness.py       run cases, compute ASR
lab/modules/         one file per module above
```
