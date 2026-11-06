# Tenglish Scam SMS Detector

Most scam detectors only understand English. Indian scam SMS often mix Telugu and English
(written in English letters). This tool flags such messages and explains why.

## How it works
1. Character n-gram TF-IDF + logistic regression (handles spelling variations in Tenglish)
2. Rule checks (KYC hook, link, urgency, OTP/PIN request, prize, loan)
3. Output: SCAM/SAFE, model score, and the reasons

## Run
```
pip install scikit-learn
python scam_detector.py
python scam_detector.py "your message here"
```

## Limits (be honest in interviews)
The included dataset is a tiny synthetic sample. Next steps: collect more labelled
messages, measure precision/recall on a held-out set, add Telugu-script support.
