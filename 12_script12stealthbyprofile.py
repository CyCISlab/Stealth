#!/usr/bin/env python3
"""
Script 12: combined Stealth Score S under each monitoring profile.

"""

import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))

PROFILES = ["M1", "M2", "M3", "M4"]



CLASS_RANGE = {
    "High": (0.80, 0.95),
    "Moderate": (0.21, 0.79),
    "Low": (0.05, 0.20),
}
X = 0.5


def path(name):
    return os.path.join(HERE, name)


def impact(severity_class, o, d, c):
    lo, hi = CLASS_RANGE[severity_class]
    i_tech = (lo + hi) / 2
    i_phys = (o + d + c) / 3
    return X * i_tech + (1 - X) * i_phys


def read(name):
    with open(path(name)) as f:
        return list(csv.DictReader(f))


ladder = {r["Incident"]: r for r in read("7_ladder_by_incident.csv")}
impact_rows = read("11_impact_table.csv")

missing = [r["Incident"] for r in impact_rows if r["Incident"] not in ladder]
if missing:
    raise SystemExit("no ladder row for: " + ", ".join(missing))

rows, disagreements = [], []

for r in impact_rows:
    incident = r["Incident"]
    i_factor = impact(r["Severity Class"],
                      int(r["o"]), int(r["d"]), int(r["c"]))
    scores = {m: round(float(ladder[incident][m]) * i_factor, 1)
              for m in PROFILES}

    published = round(float(r["S"]), 1)
    if abs(scores["M4"] - published) > 0.05:
        disagreements.append((incident, scores["M4"], published))

    rows.append({"Incident": incident, "I": round(i_factor, 3), **scores})

with open(path("12_stealth_score_by_profile.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["Incident", "I"] + PROFILES)
    w.writeheader()
    w.writerows(rows)

print(f"wrote 12_stealth_score_by_profile.csv, {len(rows)} incidents")

for m in PROFILES:
    mean = sum(r[m] for r in rows) / len(rows)
    print(f"  mean S at {m}: {mean:.1f}")

if disagreements:
    print("\nM4 does not match the published S:")
    for incident, computed, published in disagreements:
        print(f"  {incident}: computed {computed}, published {published}")
else:
    print("\nM4 reproduces the published full-coverage S for all incidents.")
