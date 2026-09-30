"""
OWNER: Person F (integration)
Insider early warning. Watermarks and the ledger catch a leak AFTER it happens; these
rules flag risky behaviour BEFORE a leak, from the audit log and the ledger:

  AFTER_HOURS   an opening between 22:00 and 06:00 IST                         (medium)
  BURST         3 or more openings by one officer within 10 minutes            (high)
  REFUSED       refused attempts (not a recipient, revoked, expired, wrong
                password at sign-to-open, admin-only action)                   (medium; high at 3+)
  LOGIN_FAILS   3 or more failed sign-ins for one username within an hour      (medium)
  SCREENSHOT    a screenshot / print attempt blocked in the protected viewer  (high)
  TAMPER        someone rewrote a ledger record                                (critical)
  LEAK          a leak case against this officer was confirmed                 (critical)

Each person gets a risk score (critical 40, high 25, medium 10), shown on the Insider watch page.
"""
import datetime
from collections import defaultdict

from . import db

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
WEIGHT = {"critical": 40, "high": 25, "medium": 10}
WINDOW_DAYS = 30


def _ist(t):
    return datetime.datetime.fromtimestamp(t, IST)


def compute(now=None):
    import time as _t
    now = now or _t.time()
    ev = db.all_events_since(now - WINDOW_DAYS * 86400)
    names = {u["username"]: u["name"] for u in db.list_users()}
    roles = {u["username"]: u["role"] for u in db.list_users()}
    out = []

    def add(kind, sev, user, t, text, doc_id=None):
        out.append({"kind": kind, "severity": sev, "username": user, "name": names.get(user, user),
                    "time": t, "text": text, "doc_id": doc_id})

    opens = defaultdict(list)
    for e in ev:
        if e["kind"] == "OPEN":
            opens[e["username"]].append(e)
            h = _ist(e["time"]).hour
            if h >= 22 or h < 6:
                add("AFTER_HOURS", "medium", e["username"], e["time"],
                    f"Opened a document at {_ist(e['time']).strftime('%H:%M')} IST, outside 06:00-22:00", e["doc_id"])
    for u, lst in opens.items():
        i = 0
        while i < len(lst):
            j = i
            while j + 1 < len(lst) and lst[j + 1]["time"] - lst[i]["time"] <= 600:
                j += 1
            if j - i + 1 >= 3:
                add("BURST", "high", u, lst[j]["time"], f"{j - i + 1} documents opened within 10 minutes")
                i = j + 1
            else:
                i += 1

    refused = defaultdict(list)
    fails = defaultdict(list)
    for e in ev:
        if e["kind"] == "DENIED" and e["username"]:
            refused[e["username"]].append(e)
        elif e["kind"] == "LOGIN_FAILED" and e["username"]:
            fails[e["username"]].append(e)
        elif e["kind"] == "SCREENSHOT" and e["username"]:
            add("SCREENSHOT", "high", e["username"], e["time"], "Tried to capture a protected document: " + (e["detail"] or ""), e["doc_id"])
        elif e["kind"] == "TAMPER":
            add("TAMPER", "critical", e["username"], e["time"], "Rewrote a ledger record: " + (e["detail"] or ""), e["doc_id"])
        elif e["kind"] == "CASE_CONFIRMED":
            who = (e["detail"] or "").split("|")[0].strip()
            if who:
                add("LEAK", "critical", who, e["time"], "Confirmed leak case: " + (e["detail"].split("|", 1)[-1].strip()), e["doc_id"])
    for u, lst in refused.items():
        add("REFUSED", "high" if len(lst) >= 3 else "medium", u, lst[-1]["time"],
            f"{len(lst)} refused attempt{'s' if len(lst) != 1 else ''} — latest: {lst[-1]['detail']}", lst[-1]["doc_id"])
    for u, lst in fails.items():
        i = 0
        for j in range(len(lst)):
            while lst[j]["time"] - lst[i]["time"] > 3600:
                i += 1
            if j - i + 1 >= 3:
                add("LOGIN_FAILS", "medium", u, lst[j]["time"], f"{j - i + 1} failed sign-ins within an hour")
                break

    out.sort(key=lambda a: a["time"], reverse=True)
    people = defaultdict(lambda: {"score": 0, "alerts": 0})
    for a in out:
        p = people[a["username"]]
        p["score"] += WEIGHT[a["severity"]]
        p["alerts"] += 1
    ranking = sorted(({"username": u, "name": names.get(u, u), "role": roles.get(u, "unknown"),
                       "score": min(100, v["score"]), "alerts": v["alerts"]} for u, v in people.items()),
                     key=lambda r: -r["score"])
    return {"alerts": out, "people": ranking,
            "counts": {s: sum(a["severity"] == s for a in out) for s in ("critical", "high", "medium")}}
