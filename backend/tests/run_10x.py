"""Runs the whole test suite 10 times, each on a brand-new temporary database,
then restarts the server on the SAME data and checks everything survived
(logins, keys, ledger verification, re-opening an old document).

Your real demo data (backend/nishaan.db + backend/store/) is never touched.
Needs port 8000 free -- stop your normal server first (Ctrl+C).

    python3 tests/run_10x.py
"""
import os
import sys
import time
import shutil
import signal
import tempfile
import subprocess

import requests

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "http://localhost:8000"


def start(env):
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"],
                         cwd=BACKEND, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    for _ in range(60):
        try:
            if requests.get(API + "/health", timeout=1).ok:
                return p
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise SystemExit("server did not start -- is something else already using port 8000?")


def stop(p):
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    p.wait(timeout=20)


def restart_checks():
    fails = []
    adm = requests.post(API + "/login", json={"username": "admin", "password": "admin123"}).json()["token"]
    rao = requests.post(API + "/login", json={"username": "rao", "password": "rao123"}).json()["token"]
    v = requests.get(API + "/ledger/verify", headers={"Authorization": "Bearer " + rao}).json()
    if not (v["ok"] and v["checked"] == 5):
        fails.append("ledger no longer verifies after restart")
    docs = requests.get(API + "/documents", headers={"Authorization": "Bearer " + rao}).json()
    r = requests.post(API + f"/open/{docs[-1]['doc_id']}", headers={"Authorization": "Bearer " + rao})
    if r.status_code != 200:
        fails.append(f"old document can't be opened after restart ({r.status_code})")
    v = requests.get(API + "/ledger/verify", headers={"Authorization": "Bearer " + adm}).json()
    if not (v["ok"] and v["checked"] == 6):
        fails.append("new block after restart doesn't chain onto the old ones")
    return fails


results = []
for i in range(1, 11):
    tmp = tempfile.mkdtemp(prefix="nishaan_run_")
    env = dict(os.environ, NISHAAN_DB=os.path.join(tmp, "test.db"), NISHAAN_STORE=os.path.join(tmp, "store"))
    p = start(env)
    r = subprocess.run([sys.executable, "tests/test_e2e.py"], cwd=BACKEND, capture_output=True, text=True)
    stop(p)
    lines = r.stdout.strip().splitlines()
    n_pass = sum(l.startswith("PASS") for l in lines)
    fails = [l for l in lines if l.startswith("FAIL")]

    p = start(env)                      # same data, fresh process = a real restart
    fails += ["FAIL - " + f for f in restart_checks()]
    stop(p)
    shutil.rmtree(tmp, ignore_errors=True)

    ok = r.returncode == 0 and not fails
    results.append(ok)
    print(f"run {i:2d}: {'PASS' if ok else 'FAIL'}  ({n_pass} checks passed + restart checks)")
    for f in fails:
        print("        " + f)

print()
print(f"{sum(results)}/10 runs fully passed")
sys.exit(0 if all(results) else 1)
