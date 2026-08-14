import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import pandas as pd

df_act = pd.read_csv('2_script2_technique_asset_map.csv')
df_det = pd.read_csv('3_script3_technique_datasource_map.csv')

LABELS = {3: 'High', 2: 'Medium', 1: 'Low', 0: 'No Gap'}


def build_map(df):
    dim_map = {}
    for _, row in df.iterrows():
        tid = str(row['Technique ID']).strip().upper()
        dim_map.setdefault(tid, set())
        if pd.notna(row['Dimension']) and str(row['Dimension']).strip():
            dim_map[tid].add(str(row['Dimension']).strip())
    return dim_map


act_map = build_map(df_act)
det_map = build_map(df_det)

names = {}
for _, row in df_act.iterrows():
    names[str(row['Technique ID']).strip().upper()] = row['Technique Name']

rows = []
for tid in sorted(act_map):
    A = act_map[tid]
    D = det_map.get(tid, set())
    gap = A - D
    rows.append({
        'Technique ID': tid,
        'Technique Name': names[tid],
        'Targeted Dimensions': ', '.join(sorted(A)),
        'Activity Size': len(A),
        'Detectable Dimensions': ', '.join(sorted(D)),
        'Gap': ', '.join(sorted(gap)),
        'Gap Size': len(gap),
        'Stealth Label': LABELS[len(gap)]
    })

df_s4 = pd.DataFrame(rows)
df_s4.to_csv('4_script4technique_stealth_categorical.csv', index=False)

counts = df_s4['Stealth Label'].value_counts()
no_activity = int((df_s4['Targeted Dimensions'] == '').sum())

print("4_Script 4 Completed")
print(f"Techniques: {len(df_s4)} | High: {counts.get('High', 0)} | Medium: {counts.get('Medium', 0)} "
      f"| Low: {counts.get('Low', 0)} | None: {counts.get('No Gap', 0)}")
print(f"Of the None group, {no_activity} have no activity set and {counts.get('No Gap', 0) - no_activity} are fully covered")
