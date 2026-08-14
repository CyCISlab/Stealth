import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import pandas as pd

df_tech = pd.read_csv('4_script4technique_stealth_categorical.csv')

with open('ics-incidents-13.json', 'r') as f:
    incidents = json.load(f)

activity_size = {}
gap_size = {}
gap_dims = {}
for _, row in df_tech.iterrows():
    tid = str(row['Technique ID']).strip().upper()
    activity_size[tid] = int(row['Activity Size'])
    gap_size[tid] = int(row['Gap Size'])
    gap_dims[tid] = {d.strip() for d in str(row['Gap']).split(',') if d.strip() and d.strip() != 'nan'}

rows = []
for inc in incidents:
    name = inc.get('name', 'Unknown')
    tech_list = inc.get('techniques', [])

    total_activity = 0
    total_gap = 0
    behavioural = 0
    gap_techniques = 0
    blind_dims = set()

    for t in tech_list:
        tid = str(t.get('external_id', '')).strip().upper()
        a = activity_size.get(tid, 0)
        if a == 0:
            continue
        behavioural += 1
        total_activity += a
        g = gap_size.get(tid, 0)
        total_gap += g
        if g > 0:
            gap_techniques += 1
            blind_dims |= gap_dims.get(tid, set())

    base = (total_gap / total_activity * 100) if total_activity > 0 else 0.0
    dominance = (gap_techniques / behavioural) if behavioural > 0 else 0.0

    rows.append({
        'Incident': name,
        'Incident ID': inc.get('external_id', ''),
        'Techniques': len(tech_list),
        'Behavioural Techniques': behavioural,
        'Sum Activity': total_activity,
        'Sum Gap': total_gap,
        'S_cov': round(base, 1),
        'Blindness Profile': ', '.join(sorted(blind_dims)) if blind_dims else 'Fully Detected',
        'Stealth Dominance': round(dominance, 3)
    })

df_base = pd.DataFrame(rows).sort_values('S_cov', ascending=False)
df_base.to_csv('5_incident_base_score.csv', index=False)

print("5_Script 5 Completed")
print(f"Incidents: {len(df_base)} | Mean S_cov: {df_base['S_cov'].mean():.1f}")
print(df_base[['Incident', 'Sum Gap', 'Sum Activity', 'S_cov', 'Stealth Dominance']].to_string(index=False))
