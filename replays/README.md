# Recorded runs

Runs recorded on real systems (the Muse Spark API, the Cisco DevNet Catalyst 8000), played back
read-only by the public demo, which has no API key and no router.

```bash
netops-copilot "..." --record replays/<name>.json --record-title "Short title"
```

Each file holds every pipeline step with its timing, the full result (intent, attempts, diffs,
findings, explanation, risk floor) and the approval outcome. No credentials, no local paths.
