import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import pandas as pd

SEVERITY_CLASS = {
    'T0879': 'High', 'T0880': 'High', 'T0827': 'High', 'T0831': 'High',
    'T0826': 'Moderate', 'T0828': 'Moderate', 'T0832': 'Moderate', 'T0837': 'Moderate',
    'T0813': 'Low', 'T0815': 'Low', 'T0829': 'Low', 'T0882': 'Low'
}

CLASS_BAND = {'High': (0.80, 0.95), 'Moderate': (0.21, 0.79), 'Low': (0.05, 0.20)}
CLASS_RANK = {'Low': 1, 'Moderate': 2, 'High': 3}

df_base = pd.read_csv('5_incident_base_score.csv')

with open('ics-incidents-13.json', 'r') as f:
    incidents = json.load(f)

impact_by_incident = {}
for inc in incidents:
    found = []
    for t in inc.get('techniques', []):
        tid = str(t.get('external_id', '')).strip().upper()
        if tid in SEVERITY_CLASS:
            found.append(tid)
    impact_by_incident[inc.get('name', 'Unknown')] = found

rows = []
for _, row in df_base.iterrows():
    name = row['Incident']
    activity = int(row['Sum Activity'])
    base = (int(row['Sum Gap']) / activity * 100) if activity > 0 else 0.0
    found = impact_by_incident.get(name, [])

    if found:
        top_class = max((SEVERITY_CLASS[t] for t in found), key=lambda c: CLASS_RANK[c])
        w_low, w_high = CLASS_BAND[top_class]
    else:
        top_class = 'None'
        w_low, w_high = 0.0, 0.0

    rows.append({
        'Incident': name,
        'Incident ID': row['Incident ID'],
        'S_cov': round(base, 1),
        'Impact Techniques': ', '.join(found) if found else '',
        'Severity Class': top_class,
        'Band Low': w_low,
        'Band High': w_high,
        'S Low': round(base * w_low, 1),
        'S High': round(base * w_high, 1),
        'Blindness Profile': row['Blindness Profile'],
        'Stealth Dominance': row['Stealth Dominance']
    })

df_s = pd.DataFrame(rows).sort_values('S_cov', ascending=False)
df_s.to_csv('6_incident_stealth_score.csv', index=False)

print("6_Script 6 Completed")
print(f"Incidents: {len(df_s)} | Classes: {dict(df_s['Severity Class'].value_counts())}")
print(df_s[['Incident', 'S_cov', 'Severity Class', 'S Low', 'S High']].to_string(index=False))
