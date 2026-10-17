# sig-baseline-checker

**The attacker didn't break the lock. They signed nothing — and nobody noticed.**

On 2026-10-05, `@subql/common@5.8.3` was poisoned after an attacker pushed an **UNSIGNED commit impersonating a maintainer who always GPG-signs**, tampered `.github/workflows/publish.yml`, then published via GitHub Actions OIDC Trusted Publisher (flatt.tech). Provenance stopped being a trust signal the moment the repo itself was compromised.

`sig-baseline-checker` learns each author's commit-signing habit from git history (sign rate, keys used), then flags signing-identity anomalies:
- **Unsigned commit from an always-signer** → CRITICAL (the subql tell)
- **Brand-new signing key** for a known author → MEDIUM
- **Unsigned commits touching release/publish paths** (workflows, setup.py, package.json, …) → HIGH

Deterministic git-history math — not a classifier.

## What it does NOT detect
Malicious code in signed commits, or compromised keys. It checks signing *identity consistency*, not code safety. A clean report means "no signing anomalies", never "this repo is safe".

## Usage
```
python -m sig_baseline_checker /path/to/repo --limit 500
```

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

