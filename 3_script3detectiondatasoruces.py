import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import pandas as pd

with open('ics-attack-17.1.json', 'r') as f:
    data = json.load(f)


DS_TO_DIM = {
    'Network Traffic': 'Cyber', 'User Account': 'Cyber', 'File': 'Cyber',
    'Command': 'Cyber', 'Process': 'Cyber', 'Script': 'Cyber',
    'Windows Registry': 'Cyber', 'Module': 'Cyber', 'Scheduled Job': 'Cyber',
    'Network Share': 'Cyber', 'Drive': 'Operational', 'Application Log': 'Operational',
    'Logon Session': 'Operational', 'Asset': 'Operational', 'Service': 'Operational',
    'Firmware': 'Physical', 'Operational Databases': 'Physical'
}

BASIS = {
    'Operational Databases': 'MITRE: "firmware changes which may be observable via operational alarms from devices"',
    'Firmware': 'MITRE: "changes made to firmware for unexpected modifications to settings"',
    'Application Log': 'MITRE: "access attempts to operational databases (e.g., historians) or other sources of operational data"',
    'Asset': 'MITRE: "Consult asset management systems to understand expected alarm settings"',
    'Network Traffic': 'Mixed: of 61 entries, 24 name ICS protocols or devices, 4 name IT artefacts, 33 generic. Single Cyber label',
    'Windows Registry': 'Guidance is IT specific, names Windows registry keys in all 5 entries',
    'Module': 'Guidance is IT specific, names DLL and script engine modules in all 3 entries',
    'Network Share': 'Guidance is IT specific, names SMB file transfer',
    'Process': 'No ICS specific guidance, assigned by the systems that produce it',
    'File': 'No ICS specific guidance, assigned by the systems that produce it',
    'Command': 'No ICS specific guidance, assigned by the systems that produce it',
    'Script': 'No ICS specific guidance, assigned by the systems that produce it',
    'Scheduled Job': 'No ICS specific guidance, assigned by the systems that produce it',
    'User Account': 'No ICS specific guidance, assigned by the systems that produce it',
    'Logon Session': 'No ICS specific guidance, assigned by the systems that produce it',
    'Drive': 'Generic operating system wording, drive letters and mount points, assigned by judgement',
    'Service': 'Generic apart from one entry naming Windows event IDs 4697 and 7045, assigned by judgement'
}

sources = {}
for obj in data['objects']:
    if obj['type'] == 'x-mitre-data-source':
        sid = ""
        for ref in obj.get('external_references', []):
            if str(ref.get('external_id', '')).startswith('DS'):
                sid = ref['external_id']
                break
        sources[obj['id']] = {'name': obj['name'], 'id': sid}

components = {}
for obj in data['objects']:
    if obj['type'] == 'x-mitre-data-component':
        parent = sources[obj['x_mitre_data_source_ref']]
        components[obj['id']] = {
            'name': obj['name'],
            'source_name': parent['name'],
            'source_id': parent['id'],
            'full': parent['name'] + ': ' + obj['name']
        }

techniques = {}
for obj in data['objects']:
    if obj['type'] == 'attack-pattern' and not obj.get('x_mitre_deprecated', False) and not obj.get('revoked', False):
        tech_id = ""
        for ref in obj.get('external_references', []):
            if ref.get('external_id', '').startswith('T0'):
                tech_id = ref['external_id']
                break
        techniques[obj['id']] = {'name': obj['name'], 'id': tech_id}

detects = {stix_id: [] for stix_id in techniques}
for obj in data['objects']:
    if obj.get('relationship_type') == 'detects':
        src = obj['source_ref']
        tgt = obj['target_ref']
        if src in components and tgt in techniques:
            detects[tgt].append(src)

tech_rows = []
for stix_id, tech in techniques.items():
    comp_refs = detects[stix_id]

    if not comp_refs:
        tech_rows.append({
            'Technique ID': tech['id'],
            'Technique Name': tech['name'],
            'Data Source Name': '',
            'Data Source ID': '',
            'Data Component': '',
            'Full Component': '',
            'Dimension': ''
        })
        continue

    for ref in comp_refs:
        comp = components[ref]
        tech_rows.append({
            'Technique ID': tech['id'],
            'Technique Name': tech['name'],
            'Data Source Name': comp['source_name'],
            'Data Source ID': comp['source_id'],
            'Data Component': comp['name'],
            'Full Component': comp['full'],
            'Dimension': DS_TO_DIM.get(comp['source_name'], 'Unknown')
        })

df_sources = pd.DataFrame(
    [{'data_source_id': s['id'], 'data_source_name': s['name']} for s in sources.values()]
).sort_values('data_source_id')
df_sources.to_csv('3_listdata_sources.csv', index=False)

df_dim = df_sources.copy()
df_dim['dimension'] = df_dim['data_source_name'].map(DS_TO_DIM)
df_dim['basis'] = df_dim['data_source_name'].map(BASIS)
df_dim.to_csv('3_datasource_dimension.csv', index=False)

df_s3 = pd.DataFrame(tech_rows, columns=[
    'Technique ID', 'Technique Name',
    'Data Source Name', 'Data Source ID',
    'Data Component', 'Full Component',
    'Dimension'
]).drop_duplicates().sort_values(['Technique ID', 'Full Component'])
df_s3.to_csv('3_script3_technique_datasource_map.csv', index=False)

print("3_Script 3 Completed")
print(f"Sources: {len(df_sources)} | Components: {len(components)} | Techniques: {df_s3['Technique ID'].nunique()} | Rows: {len(df_s3)}")
