# Threat Report to Sigma Rule Generator (with validation)

Reads a threat report, maps behaviours to MITRE ATT&CK, writes Sigma rules, then
**tests the rules on labelled events** and reports true positives, false positives and misses.
The validation step is the point: it proves a generated rule works instead of trusting it.

## Run
```
python sigma_gen.py sample_report.txt
```

## Next steps
Replace the keyword lookup with an LLM extractor (keep the validation step), add more
techniques, convert rules with sigma-cli, test on real lab logs from your own systems.
