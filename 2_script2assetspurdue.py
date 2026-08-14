
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import pandas as pd


with open('ics-attack-17.1.json', 'r') as f:
    data = json.load(f)


ASSET_INFO = {
    'Workstation': ('Level 4', 'Cyber'),
    'Routers': ('Level 4', 'Cyber'),
    'Virtual Private Network (VPN) Server': ('Level 3.5', 'Cyber'),
    'Jump Host': ('Level 3.5', 'Cyber'),
    'Application Server': ('Level 3', 'Cyber'),
    'Data Historian': ('Level 3', 'Cyber'),
    'Human-Machine Interface (HMI)': ('Level 2', 'Operational'),
    'Control Server': ('Level 2', 'Operational'),
    'Data Gateway': ('Level 2', 'Operational'),
    'Programmable Logic Controller (PLC)': ('Level 1', 'Physical'),
    'Remote Terminal Unit (RTU)': ('Level 1', 'Physical'),
    'Intelligent Electronic Device (IED)': ('Level 1', 'Physical'),
    'Safety Controller': ('Level 1', 'Physical'),
    'Field I/O': ('Level 0', 'Physical')
}


assets = {}
for obj in data['objects']:
    if obj['type'] == 'x-mitre-asset':
        aid = ""
        for ref in obj.get('external_references', []):
            if ref.get('external_id', '').startswith('A0'):
                aid = ref['external_id']
                break
        assets[obj['id']] = {'name': obj['name'], 'id': aid}

# 4. techniques (STIX id -> name, T-number)
techniques = {}
for obj in data['objects']:
    if obj['type'] == 'attack-pattern' and not obj.get('x_mitre_deprecated', False) and not obj.get('revoked', False):
        tech_id = ""
        for ref in obj.get('external_references', []):
            if ref.get('external_id', '').startswith('T0'):
                tech_id = ref['external_id']
                break
        techniques[obj['id']] = {'name': obj['name'], 'id': tech_id}


targets = {stix_id: [] for stix_id in techniques}
for obj in data['objects']:
    if obj.get('relationship_type') == 'targets':
        src = obj['source_ref']
        tgt = obj['target_ref']
        if src in techniques and tgt in assets:
            targets[src].append(tgt)


output_rows = []
for stix_id, tech in techniques.items():
    asset_refs = targets[stix_id]


    if not asset_refs:
        output_rows.append({
            'Technique Name': tech['name'],
            'Technique ID': tech['id'],
            'Asset ID': '',
            'Asset Name': '',
            'Purdue Level': '',
            'Dimension': ''
        })
        continue

    for ref in asset_refs:
        asset = assets[ref]
        level, dimension = ASSET_INFO[asset['name']]
        output_rows.append({
            'Technique Name': tech['name'],
            'Technique ID': tech['id'],
            'Asset ID': asset['id'],
            'Asset Name': asset['name'],
            'Purdue Level': level,
            'Dimension': dimension
        })


df_assets = pd.DataFrame(
    [{'asset_id': a['id'], 'asset_name': a['name']} for a in assets.values()]
).sort_values('asset_id')
df_assets.to_csv('2_listassets.csv', index=False)

df_purdue = pd.DataFrame([
    {'asset_id': a['id'],
     'asset_name': a['name'],
     'purdue_level': ASSET_INFO[a['name']][0],
     'dimension': ASSET_INFO[a['name']][1]}
    for a in assets.values()
]).sort_values('asset_id')
df_purdue.to_csv('2_asset_purdue_dimension.csv', index=False)

df_script2 = pd.DataFrame(output_rows).sort_values(['Technique ID', 'Asset ID'])
df_script2.to_csv('2_script2_technique_asset_map.csv', index=False)

print("2_Script 2 Completed")
print(f"Assets: {len(df_assets)} | Techniques: {len(techniques)} | Rows: {len(df_script2)}")
