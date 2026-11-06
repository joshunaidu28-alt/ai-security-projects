"""Flight recorder for AI agents: logs every tool call, flags risky ones, supports replay."""
import functools, json, re, time

RISKY = [
    (r"rm\s+-rf", "Destructive delete"),
    (r"curl[^|]*\|\s*(sh|bash)", "Pipe-to-shell download"),
    (r"\.env|id_rsa|/etc/shadow|aws_secret", "Secret or credential access"),
    (r"chmod\s+777", "Insecure permissions"),
]

class Recorder:
    def __init__(self, path="flight_log.jsonl"):
        self.path = path

    def _write(self, entry):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def record(self, fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.time()
            text = json.dumps({"args": args, "kwargs": kwargs}, default=str)
            flags = [why for pat, why in RISKY if re.search(pat, text, re.I)]
            result = fn(*args, **kwargs)
            self._write({"time": round(start, 2), "tool": fn.__name__, "input": text[:300],
                         "output": str(result)[:200], "risk_flags": flags,
                         "ms": round((time.time() - start) * 1000, 1)})
            return result
        return wrapper

    def replay(self):
        for i, line in enumerate(open(self.path, encoding="utf-8"), 1):
            e = json.loads(line)
            mark = "RISK " + ", ".join(e["risk_flags"]) if e["risk_flags"] else "ok"
            print(f"#{i} [{mark}] {e['tool']} <- {e['input']}")
