import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import sys

import pandas as pd

df_act = pd.read_csv('2_script2_technique_asset_map.csv')
df_det = pd.read_csv('3_script3_technique_datasource_map.csv')

with open('ics-incidents-13.json', 'r') as f:
    incidents = json.load(f)

LADDER = [
    ("M1",
     "Enterprise IT security stack. Endpoint logging plus network monitoring.",
     {"Command: Command Execution",
      "File: File Access", "File: File Creation", "File: File Deletion",
      "File: File Metadata", "File: File Modification",
      "Module: Module Load",
      "Network Share: Network Share Access",
      "Network Traffic: Network Connection Creation",
      "Network Traffic: Network Traffic Content",
      "Network Traffic: Network Traffic Flow",
      "Process: OS API Execution", "Process: Process Creation",
      "Process: Process Metadata", "Process: Process Termination",
      "Scheduled Job: Scheduled Job Creation",
      "Scheduled Job: Scheduled Job Modification",
      "Script: Script Execution",
      "User Account: User Account Authentication",
      "Windows Registry: Windows Registry Key Deletion",
      "Windows Registry: Windows Registry Key Modification"}),

    ("M2",
     "Same tooling extended into the OT network. The HMI and the engineering "
     "workstation are Windows hosts, so endpoint logging reaches them.",
     {"Logon Session: Logon Session Creation",
      "Logon Session: Logon Session Metadata",
      "Drive: Drive Creation",
      "Service: Service Creation", "Service: Service Metadata",
      "Service: Service Modification"}),

    ("M3",
     "OT native monitoring. Protocol aware IDS, asset inventory, historian "
     "integration.",
     {"Application Log: Application Log Content",
      "Asset: Asset Inventory", "Asset: Software",
      "Operational Databases: Process History/Live Data",
      "Operational Databases: Process/Event Alarm"}),

    ("M4",
     "Device level integrity. Firmware attestation and device alarm collection.",
     {"Firmware: Firmware Modification",
      "Operational Databases: Device Alarm"}),
]


act_map = {}
for _, row in df_act.iterrows():
    tid = str(row['Technique ID']).strip().upper()
    act_map.setdefault(tid, set())
    if pd.notna(row['Dimension']) and str(row['Dimension']).strip():
        act_map[tid].add(str(row['Dimension']).strip())

detect = {}
comp_dim = {}
for _, row in df_det.iterrows():
    if pd.isna(row['Full Component']) or not str(row['Full Component']).strip():
        continue
    tid = str(row['Technique ID']).strip().upper()
    comp = str(row['Full Component']).strip()
    dim = str(row['Dimension']).strip()
    detect.setdefault(tid, {})[comp] = dim
    comp_dim[comp] = dim

ALL = set(comp_dim)
IT_ONLY = {c for c, d in comp_dim.items() if d == 'Cyber'}


def score(inc, M):
    """Coverage stealth of one incident under profile M, as a percentage."""
    gap_total = act_total = 0
    for t in inc.get('techniques', []):
        tid = str(t.get('external_id', '')).strip().upper()
        A = act_map.get(tid, set())
        if not A:
            continue
        D = {dim for comp, dim in detect.get(tid, {}).items() if comp in M}
        gap_total += len(A - D)
        act_total += len(A)
    return (gap_total / act_total * 100) if act_total else 0.0


def corpus_mean(M):
    return sum(score(i, M) for i in incidents) / len(incidents)


placed, dupes = set(), set()
for _, _, add in LADDER:
    dupes |= placed & add
    placed |= add
unplaced = ALL - placed
unknown = placed - ALL

print("7_Script 7 Completed")
print(f"Catalogue: {len(ALL)} components | placed on a rung: {len(placed)} "
      f"| on two rungs: {len(dupes)} | never placed: {len(unplaced)} "
      f"| not in catalogue: {len(unknown)}")
if dupes or unplaced or unknown:
    print(f"  duplicates: {sorted(dupes)}")
    print(f"  unplaced:   {sorted(unplaced)}")
    print(f"  unknown:    {sorted(unknown)}")
    print("Ladder is not well formed. Fix before quoting any number.")
    sys.exit(1)

profiles, running = [], set()
for label, bought, add in LADDER:
    running = running | add
    profiles.append((label, bought, set(running), sorted(add)))

# The two endpoints
print()
print(f"Full catalogue ({len(ALL)} components):  mean {corpus_mean(ALL):.1f}")
print(f"IT only ({len(IT_ONLY)} Cyber components): mean {corpus_mean(IT_ONLY):.1f}")

# The ladder
summary, prev = [], None
for label, bought, M, add in profiles:
    mean = corpus_mean(M)
    step = '' if prev is None else round(prev - mean, 1)
    summary.append({
        'Rung': label,
        'What was bought': bought,
        'Components added': '; '.join(add),
        'Components total': len(M),
        'Mean coverage stealth': round(mean, 1),
        'Gain over previous rung': step
    })
    prev = mean

df_sum = pd.DataFrame(summary)
df_sum.to_csv('7_ladder_summary.csv', index=False)
print()
print(df_sum[['Rung', 'Components total', 'Mean coverage stealth',
              'Gain over previous rung']].to_string(index=False))
print(f"M4 is identical to the full catalogue: {profiles[-1][2] == ALL}")

# Per incident, plus monotonicity. Buying monitoring must never raise stealth.
rows, violations = [], []
for inc in incidents:
    vals = [score(inc, M) for _, _, M, _ in profiles]
    if any(vals[i] < vals[i + 1] - 1e-9 for i in range(len(vals) - 1)):
        violations.append(inc.get('name', '?'))
    rows.append({
        'Incident': inc.get('name', '?'),
        'IT only': round(score(inc, IT_ONLY), 1),
        **{lab: round(v, 1) for (lab, _, _, _), v in zip(profiles, vals)},
        'Full': round(score(inc, ALL), 1)
    })

df_inc = pd.DataFrame(rows).sort_values('M1', ascending=False)
df_inc.to_csv('7_ladder_by_incident.csv', index=False)
print()
print(df_inc.to_string(index=False))
print(f"Monotonicity violations: {len(violations)} of {len(incidents)}")


APPLOG = 'Application Log: Application Log Content'
m2 = profiles[1][2]
print()
print(f"{APPLOG} covers HMI application logs and historian event logs together.")
print("ATT&CK does not separate them, so the whole component sits on one rung.")
print(f"  placed at M3 as published, M2 reads {corpus_mean(m2):.1f}")
print(f"  placed at M2 instead,      M2 reads {corpus_mean(m2 | {APPLOG}):.1f}")
print(f"  swing {corpus_mean(m2) - corpus_mean(m2 | {APPLOG}):.1f} points. "
      "Rung order, monotonicity and the endpoints are unaffected either way.")
