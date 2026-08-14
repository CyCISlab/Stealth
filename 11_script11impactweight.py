#!/usr/bin/env python3
"""
Script 11: incident impact model and weighting sensitivity.

Computes, for the 13 scored incidents:

    I_tech    technique-level severity, from the highest-severity Impact
              technique of the incident, mapped to a NIST SP 800-30
              Table H-3 weight range rescaled to [0,1]
    I_phys    physical-consequence indicator, from three binary flags
              o (operator or safety-system intervention observed)
              d (confirmed physical damage or process disruption)
              c (documented cascading or multi-site effect)
    I         x * I_tech + (1-x) * I_phys
    S         base coverage score * I          (the combined Stealth Score)

and then sweeps the modelling choices: x in {0.3, 0.5, 0.7} at equal o,d,c
weights, and four o,d,c schemes at x = 0.5. Each resulting ranking is
compared to the x=0.5 / equal-weight baseline with a Spearman rank
correlation.

Inputs
    5_incident_base_score.csv          per-incident coverage score S_cov
    11_incident_impact_indicators.csv  declared o, d, c and severity class
    ics-incidents-13.json              incident technique lists
    (the severity class each incident's Impact techniques imply is
     recomputed here and printed against the declared class, so any
     re-derivation is visible rather than buried)

Outputs
    11_impact_table.csv    per-incident o, d, c, I_tech, I, S  (paper Table VIII)
    11_impact_sweep.csv    S under all seven settings, plus Spearman vs baseline
    11_impact_ranks.csv    rank of each incident under each setting

Run:  python3 11_script11impactweight.py
"""

import csv
import json
import os

from scipy.stats import spearmanr

HERE = os.path.dirname(os.path.abspath(__file__))


def path(name):
    return os.path.join(HERE, name)



# NIST SP 800-30 Table H-3, rescaled to [0,1]. Each severity class is a
# range, not a point.
CLASS_RANGE = {
    "High": (0.80, 0.95),
    "Moderate": (0.21, 0.79),
    "Low": (0.05, 0.20),
}
CLASS_ORDER = {"High": 3, "Moderate": 2, "Low": 1}

# The twelve ATT&CK for ICS Impact techniques and their severity class.
IMPACT_CLASS = {
    "T0879": "High",      # Damage to Property
    "T0880": "High",      # Loss of Safety
    "T0827": "High",      # Loss of Control
    "T0831": "High",      # Manipulation of Control
    "T0826": "Moderate",  # Loss of Availability
    "T0828": "Moderate",  # Loss of Productivity and Revenue
    "T0832": "Moderate",  # Manipulation of View
    "T0837": "Moderate",  # Loss of Protection
    "T0813": "Low",       # Denial of Control
    "T0815": "Low",       # Denial of View
    "T0829": "Low",       # Loss of View
    "T0882": "Low",       # Theft of Operational Information
}

# o, d, c weighting schemes. Equal weighting is the baseline; the other
# three each put half the weight on one indicator and split the rest.
ODC_SCHEMES = {
    "equal": (1 / 3, 1 / 3, 1 / 3),
    "intervention": (0.50, 0.25, 0.25),
    "damage": (0.25, 0.50, 0.25),
    "cascading": (0.25, 0.25, 0.50),
}

X_VALUES = [0.3, 0.5, 0.7]

# The seven settings the paper reports: three values of x at equal o,d,c
# weights, and the four o,d,c schemes at x = 0.5. The baseline setting
# (equal, 0.5) belongs to both sweeps and so is listed in both, which is
# where the count of seven rather than six comes from.
SETTINGS = ([("x-sweep", "equal", x) for x in X_VALUES]
            + [("scheme-sweep", s, 0.5) for s in ODC_SCHEMES])
BASELINE = ("scheme-sweep", "equal", 0.5)


PAPER_S = {
    "pH Sensor Spoofing Attack (Urbina Testbed)": 26.9,
    "Pump Actuator Manipulation Attack (Urbina Testbed)": 25.0,
    "2015 Ukraine Electric Power Attack": 21.7,
    "Stuxnet": 21.2,
    "Triton Safety Instrumented System Attack": 19.4,
    "2016 Ukraine Electric Power Attack": 16.7,
    "Maroochy Water Breach": 15.7,
    "Dallas Emergency Siren Attack (2017)": 10.4,
    "2022 Ukraine Electric Power Attack": 8.3,
    "Oldsmar Water Treatment Attack": 7.6,
    "German Steel Mill Attack (2014)": 7.6,
    "Unitronics Defacement Campaign": 6.0,
    "FrostyGoop Incident": 0.0,
}


# ---------------------------------------------------------------- the model

def i_tech(severity_class, point="midpoint"):
    """Collapse a severity class to a single weight.

    The class is a range. 'midpoint' is what the paper's Table VIII uses;
    'lower' is the conservative end of the same range.
    """
    lo, hi = CLASS_RANGE[severity_class]
    return (lo + hi) / 2 if point == "midpoint" else lo


def i_phys(o, d, c, weights):
    w_o, w_d, w_c = weights
    return w_o * o + w_d * d + w_c * c


def impact(severity_class, o, d, c, x, weights, point="midpoint"):
    return x * i_tech(severity_class, point) + (1 - x) * i_phys(o, d, c, weights)


def stealth_score(base_score, I):
    """S = S_cov * I * 100, with S_cov held as a percentage already."""
    return base_score * I


# ---------------------------------------------------------------- data load

def load_base_scores():
    with open(path("5_incident_base_score.csv")) as f:
        return {r["Incident"]: float(r["S_cov"]) for r in csv.DictReader(f)}


def load_indicators():
    with open(path("11_incident_impact_indicators.csv")) as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["o"], r["d"], r["c"] = int(r["o"]), int(r["d"]), int(r["c"])
    return rows


def classes_from_incident_file():
    """Severity class implied by each incident's own Impact technique list."""
    with open(path("ics-incidents-13.json")) as f:
        incidents = json.load(f)
    out = {}
    for inc in incidents:
        found = [t["external_id"] for t in inc["techniques"]
                 if t["external_id"] in IMPACT_CLASS]
        if found:
            out[inc["name"]] = max((IMPACT_CLASS[t] for t in found),
                                   key=lambda c: CLASS_ORDER[c])
        else:
            out[inc["name"]] = None
    return out



def write_table(rows, base):
    """Table VIII: per-incident indicators and S at the baseline setting."""
    _, scheme, x = BASELINE
    w = ODC_SCHEMES[scheme]
    out = []
    for r in rows:
        cls = r["Severity Class"]
        it = i_tech(cls)
        I = impact(cls, r["o"], r["d"], r["c"], x, w)
        out.append({
            "Incident": r["Incident"],
            "o": r["o"], "d": r["d"], "c": r["c"],
            "Severity Class": cls,
            "I_tech": round(it, 3),
            "I_phys": round(i_phys(r["o"], r["d"], r["c"], w), 3),
            "I": round(I, 3),
            "S_cov": base[r["Incident"]],
            "S": round(stealth_score(base[r["Incident"]], I), 1),
        })
    out.sort(key=lambda z: -z["S"])
    with open(path("11_impact_table.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        wr.writeheader()
        wr.writerows(out)
    return out


def sweep(rows, base):
    """All seven settings, with Spearman against the baseline ranking."""
    scores = {}
    for setting in SETTINGS:
        _, scheme, x = setting
        w = ODC_SCHEMES[scheme]
        scores[setting] = {
            r["Incident"]: stealth_score(
                base[r["Incident"]],
                impact(r["Severity Class"], r["o"], r["d"], r["c"], x, w))
            for r in rows
        }

    names = [r["Incident"] for r in rows]
    ref = [scores[BASELINE][n] for n in names]

    sweep_rows, rank_rows = [], []
    for setting in SETTINGS:
        sweep_name, scheme, x = setting
        vals = [scores[setting][n] for n in names]
        rho, p = spearmanr(ref, vals)
        top5 = [n for n, _ in sorted(scores[setting].items(),
                                     key=lambda kv: -kv[1])[:5]]
        sweep_rows.append({
            "Sweep": sweep_name,
            "o,d,c scheme": scheme,
            "x": x,
            "Spearman rho vs baseline": round(rho, 3),
            "p": round(p, 5),
            "Top five": "; ".join(top5),
        })
        order = sorted(names, key=lambda n: -scores[setting][n])
        for pos, n in enumerate(order, 1):
            rank_rows.append({
                "Incident": n,
                "Sweep": sweep_name,
                "o,d,c scheme": scheme,
                "x": x,
                "S": round(scores[setting][n], 2),
                "Rank": pos,
            })

    with open(path("11_impact_sweep.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(sweep_rows[0].keys()))
        wr.writeheader()
        wr.writerows(sweep_rows)
    with open(path("11_impact_ranks.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rank_rows[0].keys()))
        wr.writeheader()
        wr.writerows(rank_rows)

    return scores, sweep_rows


# ---------------------------------------------------------------------- main

def main():
    base = load_base_scores()
    rows = load_indicators()
    implied = classes_from_incident_file()

    print("=" * 78)
    print("SEVERITY CLASS: implied by the incident file vs. the class used")
    print("=" * 78)
    for r in rows:
        name, used = r["Incident"], r["Severity Class"]
        imp = implied.get(name)
        mark = "  " if imp == used else "->"
        print(f"{mark} {name[:46]:48s} file={str(imp):9s} used={used:9s} "
              f"({r['Class Source']})")
    overrides = [r["Incident"] for r in rows
                 if implied.get(r["Incident"]) != r["Severity Class"]]
    print(f"\n{len(overrides)} incident(s) re-derived away from the incident "
          f"file: {', '.join(overrides)}")

    table = write_table(rows, base)
    print("\n" + "=" * 78)
    print("TABLE VIII  (x = 0.5, equal o,d,c weights, I_tech at class midpoint)")
    print("=" * 78)
    print(f"{'Incident':46s} {'o':>2s} {'d':>2s} {'c':>2s} "
          f"{'I_tech':>7s} {'I':>6s} {'S':>6s}")
    for t in table:
        print(f"{t['Incident'][:44]:46s} {t['o']:2d} {t['d']:2d} {t['c']:2d} "
              f"{t['I_tech']:7.3f} {t['I']:6.3f} {t['S']:6.1f}")

    scores, sweep_rows = sweep(rows, base)
    print("\n" + "=" * 78)
    print(f"WEIGHTING SENSITIVITY: {len(SETTINGS)} settings vs. the baseline "
          f"ranking")
    print("=" * 78)
    for s in sweep_rows:
        print(f"  {s['Sweep']:13s} scheme={s['o,d,c scheme']:13s} "
              f"x={s['x']:<4} rho={s['Spearman rho vs baseline']:.3f}  "
              f"p={s['p']:.5f}")
    rhos = [s["Spearman rho vs baseline"] for s in sweep_rows]
    print(f"\n  Spearman range across all {len(SETTINGS)} settings: "
          f"[{min(rhos):.2f}, {max(rhos):.2f}]")

    # Top-five stability.
    names = [r["Incident"] for r in rows]
    counts = {n: 0 for n in names}
    for setting in SETTINGS:
        for n in sorted(scores[setting], key=lambda z: -scores[setting][z])[:5]:
            counts[n] += 1
    print(f"\n  Top-five membership across the {len(SETTINGS)} settings:")
    for n, k in sorted(counts.items(), key=lambda kv: -kv[1]):
        if k:
            print(f"    {n[:50]:52s} {k}/{len(SETTINGS)}")

    # Oldsmar vs German Steel Mill, the tie discussed in the appendix.
    print("\n" + "=" * 78)
    print("OLDSMAR vs GERMAN STEEL MILL under each o,d,c scheme")
    print("=" * 78)
    pair = ["Oldsmar Water Treatment Attack", "German Steel Mill Attack (2014)"]
    for scheme in ODC_SCHEMES:
        key = ("scheme-sweep", scheme, 0.5)
        a, b = (scores[key][p] for p in pair)
        lead = "tie" if abs(a - b) < 0.005 else (
            "Oldsmar ahead" if a > b else "German Steel ahead")
        print(f"  {scheme:13s} Oldsmar={a:5.2f}  German Steel={b:5.2f}  {lead}")

    # ----------------------------------------------------------- verification
    print("\n" + "=" * 78)
    print("VERIFICATION against the values printed in the paper")
    print("=" * 78)
    bad = 0
    for t in table:
        want = PAPER_S.get(t["Incident"])
        if want is None:
            continue
        ok = abs(t["S"] - want) <= 0.1
        bad += 0 if ok else 1
        print(f"  {'ok ' if ok else 'BAD'} {t['Incident'][:46]:48s} "
              f"script={t['S']:6.1f}  paper={want:6.1f}")
    print(f"\n  {'ALL VALUES MATCH' if not bad else str(bad) + ' MISMATCH(ES)'}")
    print(f"  wrote 11_impact_table.csv, 11_impact_sweep.csv, "
          f"11_impact_ranks.csv")


if __name__ == "__main__":
    main()
