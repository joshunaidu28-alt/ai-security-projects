# Prompt Injection Tester

Sends a set of attack prompts to a chatbot and checks if a hidden canary secret leaks.
Includes a mock vulnerable bot and a hardened bot so you can see the before/after.

## Run
```
python injection_tester.py
```

## Test your own app
Replace `vulnerable_bot` with a function that calls your own chatbot. Only test apps you own
or have written permission to test.

## Next steps
Add more attack categories, score severity, add indirect injection (poisoned documents).
