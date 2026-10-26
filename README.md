# Sentinel SOC — Starter

A small, offline Python security-event analyzer for learning JSON, dictionaries, lists, loops, conditions, and functions.

## Run

Open this folder in VS Code and run:

```powershell
python soc_analyzer.py
```

No third-party packages are needed. The script reads `security_events.json` from its own folder.

## Next exercise

1. Run the script and inspect the output.
2. In `main()`, print the three most frequent failed-login IPs.
3. Create `failed_logins_by_user(events)` using `failed_logins_by_ip()` as a guide.
4. Test against `security_events_messy.json` by changing the filename in `main()`.

These are synthetic training datasets, not live monitoring data.
