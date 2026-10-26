"""A tiny in-memory RAG store: TF-IDF cosine retrieval with document metadata. No external deps."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

_TOKEN = re.compile(r"[a-z0-9]+")
STOPWORDS = set("the a an is are of to and or for in on at with by be this that it what how do does".split())


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in STOPWORDS]


@dataclass
class Doc:
    id: str
    text: str
    source: str = "policy_portal"
    tenant: str = "shared"
    date: str = "2025-01-01"
    poisoned: bool = False
    meta: dict = field(default_factory=dict)


class Store:
    def __init__(self, docs: list[Doc]):
        self.docs = docs
        self.tfs = [Counter(tokenize(d.text)) for d in docs]
        df = Counter(t for tf in self.tfs for t in tf)
        n = len(docs)
        self.idf = {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df.items()}
        self.vecs = [self._vec(tf) for tf in self.tfs]

    def _vec(self, tf: Counter) -> dict:
        v = {t: c * self.idf.get(t, 1.0) for t, c in tf.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def search(self, query: str, k: int = 4, allowed=None) -> list[tuple[Doc, float]]:
        q = self._vec(Counter(tokenize(query)))
        scored = []
        for doc, vec in zip(self.docs, self.vecs):
            if allowed and not allowed(doc):
                continue
            score = sum(w * vec.get(t, 0.0) for t, w in q.items())
            scored.append((doc, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]
