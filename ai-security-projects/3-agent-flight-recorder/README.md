# AI Agent Flight Recorder

AI agents call tools (shell, files, web). This records every call, flags risky ones, and
lets you replay what the agent did, like a black box in an aircraft.

## Run
```
python demo.py
```

## Use with your own agent
Wrap each tool function with `@rec.record`.

## Next steps
Block risky calls until a human approves, add a web dashboard, add secrets redaction in logs.
