"""Tests for sig_baseline_checker (synthetic commit data; no git needed)."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sig_baseline_checker import (  # noqa: E402
    learn_baselines, flag_anomalies, _touches_release)

PASS, FAIL = [], []


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print("PASS  " + name)
    except Exception as e:  # noqa: BLE001
        FAIL.append((name, repr(e)))
        print("FAIL  %s: %r" % (name, e))


def _commit(sha, author, signed, key=None, files=(), subject="fix"):
    return {"sha": sha, "author": author, "email": author + "@x",
            "date": "2026-10-01", "signed": signed, "key": key,
            "subject": subject, "files": list(files)}


def _always_signer(n=6):
    return [_commit("a%02d" % i, "Alice", True, key="KEY1",
                    files=["src/a.py"]) for i in range(n)]


def t_always_signer_baseline():
    b = learn_baselines(_always_signer())
    assert b["Alice"]["always_signs"] is True
    assert b["Alice"]["sign_rate"] == 1.0
    assert b["Alice"]["keys"] == ["KEY1"]


def t_unsigned_by_always_signer_critical():
    # Baseline learned from history; anomaly checked against it.
    b = learn_baselines(_always_signer())
    commits = _always_signer() + [_commit("bad01", "Alice", False,
                                          files=["src/b.py"])]
    f = flag_anomalies(commits, b)
    hit = [x for x in f if x["finding"] == "unsigned-by-always-signer"]
    assert len(hit) == 1 and hit[0]["severity"] == "CRITICAL"
    assert "subql" in hit[0]["detail"]


def t_new_key_medium():
    commits = _always_signer() + [_commit("k01", "Alice", True, key="KEY9")]
    b = learn_baselines(_always_signer())
    f = flag_anomalies(commits, b)
    assert any(x["finding"] == "new-signing-key" and x["severity"] == "MEDIUM"
               for x in f)


def t_unsigned_release_touch_high():
    commits = ([_commit("u%02d" % i, "Bob", False, files=["src/x.py"])
                for i in range(6)]
               + [_commit("rel01", "Bob", False,
                          files=[".github/workflows/publish.yml"])])
    b = learn_baselines(commits)
    f = flag_anomalies(commits, b)
    assert any(x["finding"] == "unsigned-release-touch" and
               x["severity"] == "HIGH" for x in f)


def t_insufficient_history_info():
    commits = [_commit("n01", "Newt", False, files=["a.py"])]
    b = learn_baselines(commits)
    assert b["Newt"]["sign_rate"] is None
    f = flag_anomalies(commits, b)
    assert any(x["finding"] == "no-signing-baseline" for x in f)


def t_touches_release_paths():
    assert _touches_release([".github/workflows/ci.yml"]) != []
    assert _touches_release(["setup.py"]) != []
    assert _touches_release(["src/main.py"]) == []


def t_clean_history_no_critical():
    b = learn_baselines(_always_signer())
    f = flag_anomalies(_always_signer(), b)
    assert not [x for x in f if x["severity"] == "CRITICAL"]


def test_all_checks():
    for name, fn in sorted(
            [(k, v) for k, v in globals().items() if k.startswith("t_")]):
        check(name, fn)
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    assert not FAIL


if __name__ == "__main__":
    test_all_checks()
