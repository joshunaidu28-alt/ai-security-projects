"""Scam SMS detector for Telugu-English (Tenglish) and English messages.
Combines a small ML model with human-readable rules so every verdict has a reason."""
import csv, re, sys
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

RULES = [
    (r"kyc", "Mentions KYC update (common scam hook)"),
    (r"https?://\S+|bit\.ly|tinyurl", "Contains a link"),
    (r"\bloan\b|\bemi\b", "Loan offer"),
    (r"urgent|immediately|today only|block|suspend|freeze", "Urgency or threat"),
    (r"\botp\b|\bpin\b|\bcvv\b|password", "Asks for sensitive info"),
    (r"lakh|crore|lottery|prize|reward", "Prize or large money"),
    (r"telegram|work from home", "Task or job scam wording"),
]

def load(path="data.csv"):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return [r["text"] for r in rows], [int(r["label"]) for r in rows]

def build_model(path="data.csv"):
    X, y = load(path)
    model = make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), lowercase=True),
        LogisticRegression(max_iter=1000),
    )
    return model.fit(X, y)

def analyze(model, text):
    prob = float(model.predict_proba([text])[0][1])
    hits = [why for pat, why in RULES if re.search(pat, text, re.I)]
    scam = prob >= 0.5 or len(hits) >= 3
    return {"scam": scam, "model_score": round(prob, 2), "reasons": hits}

if __name__ == "__main__":
    model = build_model()
    msgs = sys.argv[1:] or [
        "Mee bank account block avtundi, ippude KYC update cheyyandi http://bank-kyc.xyz",
        "Repu 10 ki office lo kaluddam macha",
    ]
    for m in msgs:
        r = analyze(model, m)
        print(("SCAM " if r["scam"] else "SAFE ") + f"(score {r['model_score']}) :: {m}")
        for why in r["reasons"]:
            print("   -", why)
