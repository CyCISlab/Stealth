
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import pandas as pd

# 1. Load MITRE ICS 17.1
with open('ics-attack-17.1.json', 'r') as f:
    data = json.load(f)

# Official MITRE ICS Tactic Order
ORDER = ['TA0108','TA0104','TA0110','TA0111','TA0103','TA0102','TA0109','TA0100','TA0101','TA0107','TA0106','TA0105']
IMPACT_TACTICS = ['TA0107', 'TA0106', 'TA0105']

# 2. Build Tactic Map 
tactic_map = {}
for obj in data['objects']:
    if obj['type'] == 'x-mitre-tactic':
        sn = obj['x_mitre_shortname']
        fullname = obj['name']
      
        tid = ""
        for ref in obj.get('external_references', []):
            if 'TA' in ref.get('external_id', ''):
                tid = ref['external_id']
                break
        tactic_map[sn] = {'name': fullname, 'id': tid}

# 3. Map Techniques to Tactics
rows = []
for obj in data['objects']:
    if obj['type'] == 'attack-pattern' and not obj.get('x_mitre_deprecated', False) and not obj.get('revoked', False):
        
        tech_id = ""
        for ref in obj.get('external_references', []):
            if ref.get('external_id', '').startswith('T0'):
                tech_id = ref['external_id']
                break
        tech_name = obj['name']
        
        for phase in obj.get('kill_chain_phases', []):
            sn = phase['phase_name']
            if sn in tactic_map:
                t_info = tactic_map[sn]
                rows.append({
                    'Phase': "Impact" if t_info['id'] in IMPACT_TACTICS else "Pre-Impact",
                    'Tactic Name': t_info['name'],
                    'Tactic ID': t_info['id'],
                    'Technique Name': tech_name,
                    'Technique ID': tech_id
                })

df_s1 = pd.DataFrame(rows)
df_s1['Rank'] = df_s1['Tactic ID'].apply(lambda x: ORDER.index(x) if x in ORDER else 99)
df_s1 = df_s1.sort_values(['Rank', 'Technique ID']).drop(columns='Rank')
df_s1.to_csv('1_script1_tactical_framework.csv', index=False)
print("1_Script 1 Completed")