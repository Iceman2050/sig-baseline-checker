# sig-baseline-checker

**Supply-chain attackers don't need to break crypto — they just need one unsigned commit to slip in.**

The subql incident (Oct 2026) showed signing gaps are the norm, not the exception. This tool builds a per-author commit-signing baseline for any git repo and flags anomalies: unsigned commits from usually-signing authors, new signers, missing baselines.

## 30-second quickstart
```
python sig_baseline_checker.py /path/to/repo --limit 500
```

## Example output
```
{
  "commits_analyzed": 1,
  "authors": 1,
  "findings": [
    {
      "sha": "763496e9fe0a",
      "author": "Iceman2050",
      "finding": "no-signing-baseline",
      "severity": "INFO",
      "detail": "Iceman2050 has only 1 commit(s) in history — no signing baseline yet; review manually."
    }
  ],
  "verdict": "1 signing anomal(ies)"
}
```

`repo` defaults to `.`, `--limit` caps commits analyzed (default 500).

## What it does NOT do
It reads git history — it can't verify signatures against a keyserver or prove a commit wasn't forged with a stolen key. Baseline quality depends on history depth.

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI



> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
