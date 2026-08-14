import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json

import pandas as pd


MIN_TECHNIQUES = 5

df_tech = pd.read_csv('4_script4technique_stealth_categorical.csv')

with open('ics-incidents-13.json', 'r') as f:
    incidents = json.load(f)

activity_size = {}
gap_size = {}
for _, row in df_tech.iterrows():
    tid = str(row['Technique ID']).strip().upper()
    activity_size[tid] = int(row['Activity Size'])
    gap_size[tid] = int(row['Gap Size'])


def base_score(tids):
    """Coverage stealth over a list of techniques, as a percentage.
    Techniques with an empty activity set, the 12 impact techniques, never
    contribute, so they cannot move the score."""
    total_gap = total_activity = 0
    for tid in tids:
        a = activity_size.get(tid, 0)
        if a == 0:
            continue
        total_activity += a
        total_gap += gap_size.get(tid, 0)
    return (total_gap / total_activity * 100) if total_activity > 0 else 0.0


rows = []
for inc in incidents:
    tids = [str(t.get('external_id', '')).strip().upper()
            for t in inc.get('techniques', [])]
    behavioural = [t for t in tids if activity_size.get(t, 0) > 0]

    base = base_score(tids)

    # Jackknife. Remove one behavioural technique at a time and rescore.
    jk = [base_score(tids[:i] + tids[i + 1:])
          for i, t in enumerate(tids) if activity_size.get(t, 0) > 0]
    jk_min = min(jk) if jk else base
    jk_max = max(jk) if jk else base

    sparse = len(tids) < MIN_TECHNIQUES
    fragile = base > 0 and jk_min == 0
    reasons = []
    if sparse:
        reasons.append(f'fewer than {MIN_TECHNIQUES} techniques')
    if fragile:
        reasons.append('whole gap rests on one technique')

    rows.append({
        'Incident': inc.get('name', 'Unknown'),
        'Incident ID': inc.get('external_id', ''),
        'Techniques': len(tids),
        'Behavioural Techniques': len(behavioural),
        'S_cov': round(base, 1),
        'Stability Min': round(jk_min, 1),
        'Stability Max': round(jk_max, 1),
        'Confidence': 'Low' if reasons else 'High',
        'Reason': '; '.join(reasons) if reasons else 'stable'
    })

df_v = pd.DataFrame(rows).sort_values('S_cov', ascending=False)
df_v.to_csv('8_incident_validation.csv', index=False)

low = df_v[df_v['Confidence'] == 'Low']
stable_10 = df_v[(df_v['Techniques'] >= 10) & (df_v['Stability Min'] > 0)]

print("8_Script 8 Completed")
print(f"Incidents: {len(df_v)} | High confidence: {(df_v['Confidence'] == 'High').sum()} "
      f"| Low confidence: {len(low)}")
print(f"Incidents with 10 or more techniques that are stable: "
      f"{len(stable_10)} of {(df_v['Techniques'] >= 10).sum()}")
print()
print(df_v[['Incident', 'Techniques', 'S_cov', 'Stability Min',
            'Stability Max', 'Confidence']].to_string(index=False))
