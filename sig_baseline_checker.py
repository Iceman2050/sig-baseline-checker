"""sig-baseline-checker: per-author commit-signing baselines from git
history; flag signing-identity anomalies.

Hook (2026-10-05): @subql/common@5.8.3 was poisoned after an attacker
pushed an UNSIGNED commit impersonating a maintainer who always
GPG-signs, tampered .github/workflows/publish.yml, then published via
GitHub Actions OIDC Trusted Publisher (flatt.tech). Provenance is no
longer a trust signal when the repo itself is compromised.

Learns each author's signing habit (% of commits signed, keys used),
then flags: unsigned commits from authors who always sign, brand-new
signing keys, and unsigned commits touching release/publish paths.
Deterministic git-history math — not a classifier.
"""

import re
import subprocess

VERSION = "1.0.0"

# Paths whose unsigned modification is release-grade risk.
RELEASE_PATHS = (
    ".github/workflows/", "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", "package-lock.json", "Makefile", "Dockerfile",
    "release/", ".goreleaser", "cargo.toml", "go.mod",
)

# `git log --format` fields, \x1f-separated, \x1e record separator.
LOG_FORMAT = "%H%x1f%an%x1f%ae%x1f%ad%x1f%G?%x1f%GK%x1f%s%x1e"


def collect_commits(repo_dir=".", limit=500):
    """Collect commit records via git log. Each record:
    {"sha", "author", "email", "date", "signed", "key", "subject", "files"}."""
    out = subprocess.run(
        ["git", "-C", repo_dir, "log", "--format=" + LOG_FORMAT,
         "--name-only", "--date=short", "-n", str(limit)],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError("git log failed: %s" % out.stderr.strip()[:200])
    commits = []
    for record in out.stdout.split("\x1e"):
        record = record.strip()
        if not record:
            continue
        lines = record.split("\n")
        fields = lines[0].split("\x1f")
        if len(fields) < 7:
            continue
        sha, author, email, date, gpg, key, subject = fields[:7]
        commits.append({
            "sha": sha,
            "author": author,
            "email": email,
            "date": date,
            "signed": gpg in ("G", "U"),  # G=valid, U=valid unknown validity
            "key": key or None,
            "subject": subject,
            "files": [l for l in lines[1:] if l.strip()],
        })
    return commits


def learn_baselines(commits, min_commits=5):
    """Learn per-author signing baselines.

    Returns {author: {"total", "signed", "sign_rate", "keys",
                      "always_signs"}}. Authors below min_commits get
    sign_rate None (insufficient history).
    """
    stats = {}
    for c in commits:
        s = stats.setdefault(c["author"],
                             {"total": 0, "signed": 0, "keys": set()})
        s["total"] += 1
        if c["signed"]:
            s["signed"] += 1
            if c["key"]:
                s["keys"].add(c["key"])
    baselines = {}
    for author, s in stats.items():
        rate = (s["signed"] / s["total"]) if s["total"] >= min_commits else None
        baselines[author] = {
            "total": s["total"],
            "signed": s["signed"],
            "sign_rate": rate,
            "keys": sorted(s["keys"]),
            "always_signs": rate == 1.0,
        }
    return baselines


def _touches_release(files):
    return [f for f in files
            if any(f.startswith(p) or f == p.rstrip("/") for p in RELEASE_PATHS)]


def flag_anomalies(commits, baselines):
    """Flag signing-identity anomalies. Returns findings list."""
    findings = []
    for c in commits:
        b = baselines.get(c["author"], {})
        rate = b.get("sign_rate")
        # 1. Unsigned commit from an author who always signs -> CRITICAL.
        if not c["signed"] and b.get("always_signs"):
            findings.append({
                "sha": c["sha"][:12],
                "author": c["author"],
                "finding": "unsigned-by-always-signer",
                "severity": "CRITICAL",
                "detail": ("%s always signs (%d/%d signed) but commit %s is "
                           "unsigned — the subql poisoning tell (Oct 2026)."
                           % (c["author"], b["signed"], b["total"],
                              c["sha"][:12])),
            })
        # 2. New signing key for a known author -> MEDIUM.
        if c["signed"] and c["key"] and c["key"] not in b.get("keys", []):
            findings.append({
                "sha": c["sha"][:12],
                "author": c["author"],
                "finding": "new-signing-key",
                "severity": "MEDIUM",
                "detail": ("Commit signed with a key never seen for %s: %s — "
                           "verify the key belongs to the author."
                           % (c["author"], c["key"])),
            })
        # 3. Unsigned commit touching release paths -> HIGH.
        rel = _touches_release(c["files"])
        if not c["signed"] and rel and not b.get("always_signs"):
            findings.append({
                "sha": c["sha"][:12],
                "author": c["author"],
                "finding": "unsigned-release-touch",
                "severity": "HIGH",
                "detail": ("Unsigned commit touches release/publish paths: "
                           "%s." % ", ".join(rel[:5])),
            })
        # 4. Author with insufficient history signing for the first time.
        if rate is None and b.get("total", 0) > 0 and not c["signed"]:
            findings.append({
                "sha": c["sha"][:12],
                "author": c["author"],
                "finding": "no-signing-baseline",
                "severity": "INFO",
                "detail": ("%s has only %d commit(s) in history — no signing "
                           "baseline yet; review manually."
                           % (c["author"], b.get("total", 0))),
            })
    return findings


def check(repo_dir=".", limit=500):
    commits = collect_commits(repo_dir, limit)
    baselines = learn_baselines(commits)
    findings = flag_anomalies(commits, baselines)
    return {
        "commits_analyzed": len(commits),
        "authors": len(baselines),
        "findings": findings,
        "verdict": ("CLEAN — no signing-identity anomalies" if not findings
                    else "%d signing anomal(ies)" % len(findings)),
    }


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(
        description="Per-author commit-signing baselines; flag "
                    "signing-identity anomalies.")
    ap.add_argument("repo", nargs="?", default=".",
                    help="git repo directory (default: .)")
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args(argv)
    try:
        print(json.dumps(check(args.repo, args.limit), indent=2))
    except RuntimeError as e:
        print("ERROR: %s" % e)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
