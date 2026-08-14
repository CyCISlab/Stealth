# Man-BK Framework

## 1. 3DIM: Cyber, Operational, Physical

In order to analyse the incidents, we separated the layers into three dimensions: Cyber, Operational and Physical.

**Cyber:** the IT part. Ordinary computers with an operating system, user accounts and network connections.

**Operational:** the layer between the human and the plant. Where the process is watched and commands are sent to it.

**Physical:** the lowest level. The devices that read from and act on the process directly.

## 2. MITRE ATT&CK

MITRE ATT&CK is a public catalogue of attacker behaviour, organised as tactics, meaning what the attacker is trying to achieve, and techniques, meaning how they achieve it. It is widely used in both academia and industry as a common vocabulary for describing attacks, and MITRE publishes a separate matrix for ICS.

We use ICS version 17.1, `ics-attack-17.1.json`.

### a. Tactics and techniques

The MITRE ICS matrix consists of 12 tactics and 83 techniques. `1_script1tactictechnique.py` extracts them from the JSON and writes `1_script1_tactical_framework.csv`. Deprecated ones are excluded.

We then divide the tactics into two groups. Pre-impact covers the nine tactics the attacker uses to prepare and carry out the intrusion. Impact group covers the three tactics that are Impact, Impair Process Control and Inhibit Response Function. The techniques under MITRE Impact tactics, they describe the result of an attack rather than an action against a system. They therefore contribute nothing to the activity set. We use them to set the impact weight in the scoring step.

`1_script1tactictechnique.py` also labels each row Pre-Impact or Impact. That label is descriptive and does not affect any score.

### b. Targeted assets and Purdue levels

MITRE lists a Targeted Assets section on each technique, showing which assets that technique can act on. First we extract the 14 assets from the JSON, `2_listassets.csv`.

**Purdue level:** the Purdue model is the standard way of drawing an OT network in layers, from the field devices at the bottom up to the business network at the top. It makes it clear where in the plant something is happening.

We assign one to each of the 14 assets to Purdue levels, then group those levels into the three dimensions, `2_asset_purdue_dimension.csv`.

`2_script2assetspurdue.py` does this and writes `2_script2_technique_asset_map.csv`, one row per technique and asset, with the asset ID, the Purdue level and the dimension. This is the activity set.

### c. Detection and data sources

MITRE also lists a Detection section on techniques, showing what you would have to be able to see in order to catch it. First we extract the 17 data sources and their 36 data components from the JSON, of which 34 are used by ICS techniques, `3_listdata_sources.csv`.

We assign one of the three dimensions to each of the 17 data sources, and each component takes the dimension of its source. Across the 34 used components this gives 10 sources and 21 components in Cyber, 5 sources and 9 components in Operational, and 2 sources and 4 components in Physical, `3_datasource_dimension.csv`.

`3_script3detectiondatasoruces.py` does this and writes `3_script3_technique_datasource_map.csv`, one row for each technique and data component, with the data source name and ID, the full component name and the dimension. This is the detection set.

## 3. Incidents

To test the framework we collected 13 ICS attacks, both real world incidents and academic testbed scenarios, and mapped each one to its MITRE techniques and tactics, `ics-incidents-13.json`.

**Mapping from a report:** we take each action described in the report, find the technique that matches it in the 83, and record the reference that supports it. If no source describes an action, we do not include the technique.

## 4. Framework

### a. Technique level gap

For each technique we now have two things: the dimensions it acts on, from step 2b, and the dimensions it can be seen in, from step 2c. We compare them.

**Gap:** the dimensions a technique acts on that it cannot be seen in. We take the targeted dimensions and remove the detectable ones. What is left is where the attacker is working unobserved.

`4_script4coring.py` does this for all 83 techniques and writes `4_script4technique_stealth_categorical.csv`, one row per technique with its targeted dimensions, its detectable dimensions, the gap, and a label based on the size of the gap.

### b. From technique to incident

An incident is a list of techniques, so we score it by adding its techniques together.

For each technique in the incident we take two numbers from step 4a, the size of its activity set and the size of its gap. We add the gaps across the whole incident, add the activities across the whole incident, divide one by the other and multiply by 100. This is the coverage stealth score S_cov, the share of the attack's activity that the defender could not see.

We add before dividing rather than averaging the techniques. A technique that touches all three dimensions should count for more than one that touches a single dimension, and adding first is what gives it that weight.

`5_script5incidentscore.py` reads `4_script4technique_stealth_categorical.csv` and writes `5_incident_base_score.csv`.

### c. Impact weights

S_cov says how much of the attack was invisible. It does not say whether the attack mattered. An intrusion that hides perfectly but changes nothing should not score the same as one that hides perfectly and destroys equipment. The weight is what separates them.

We use the 12 Impact techniques from step 2a. An incident takes the class of its highest Impact technique, because an attack is as severe as its worst outcome.

Each of the 12 Impact techniques belongs to a severity class from FIPS 199, High, Moderate or Low. Each class carries a range of values taken from NIST SP 800-30 Table H-3, High 0.80 to 0.95, Moderate 0.21 to 0.79, Low 0.05 to 0.20. We multiply S_cov by both ends, so the final score S is a range. This keeps the choice of weight visible instead of hiding it in one number.

`6_script6impactweight.py` reads `5_incident_base_score.csv` and writes `6_incident_stealth_score.csv`.

### d. Results

`6_incident_stealth_score.csv` holds the 13 incidents with their S_cov, their Impact techniques, their severity class, the band, and the two ends of S.

Two other columns describe where the blindness sits rather than how large it is.

**Blindness profile:** which of the three dimensions the gaps fell in. S_cov says how much the defender missed, the blindness profile says which layer it was missed in. Physical appears in 11 of the 13 incidents, Cyber in only one, Stuxnet. The defender is least able to see the layer closest to the process.

**Stealth dominance:** the share of an incident's behavioural techniques that have any gap at all. S_cov says how much of the attack was invisible, dominance says whether that came from a few deep blind spots or from many shallow ones. It separates incidents that share the same score. Oldsmar and German Steel Mill both score 12.5 and both have a dominance of 0.25, so in each case the blindness sits in one technique rather than spread across all of them.

### e. Deployed detection profiles

Steps 4a to 4d assume the defender collects everything, M = C, all 34 data components. That is the best case, so the scores there are a floor.

A deployed detection profile M is the set of data components a site actually collects. A technique is only detectable in a dimension if at least one deployed component that detects it sits in that dimension:

```
D_t(M) = { dim(c) : c in C_t and c in M }
G_t(M) = A_t \ D_t(M)
```

Only the detection side moves. The activity set A_t stays the same, because what the attacker touches does not depend on what the defender bought.

`7_script7deploymentprofile.py` does this. It reads `2_script2_technique_asset_map.csv`, `3_script3_technique_datasource_map.csv` and `ics-incidents-13.json`, and writes `7_ladder_summary.csv` and `7_ladder_by_incident.csv`.

Profiles are written as lists of data components, not as equipment names. ATT&CK gives no asset label to a data component, so a profile cannot be stated in device language.

There are four profiles, and each one keeps everything the one below it has, so the count given is the running total. M1 is an enterprise IT security stack, endpoint logging and network monitoring, 21 components. M2 extends the same tooling into the OT network by adding logon sessions, drive creation and Windows service logs, which takes it to 27. M3 adds OT native monitoring, a protocol aware IDS, asset inventory and historian integration, which takes it to 32. M4 adds device level integrity, firmware attestation and device alarms, which takes it to 34.

M1 is the IT only profile used in the main results. M4 is the full catalogue, so there is no fifth profile.

### f. Validation

We cannot prove the scores are correct, because nobody knows the true stealth of Stuxnet, so there is nothing to compare against. Instead we check two weaker things. That the score behaves the way the model says it should, and that the results survive being poked. There are five checks.

**Stability, jackknife, leave one out.** We remove one technique from an incident, recompute its score, put it back, and do the same for every technique in turn. The lowest and highest scores we get become the stability range. If the range is narrow, the score does not depend on any single technique. If removing one technique drops the score to zero, the whole gap was resting on that one technique. Every incident with ten or more techniques comes out stable.

**Confidence.** Two rules decide whether a score is trustworthy. If the incident has fewer than five techniques, it is Low. If the stability range reaches zero, it is Low. Anything else is High. Five incidents are Low, Dallas, FrostyGoop, Oldsmar, German Steel Mill and Unitronics. The other eight are High. Low confidence scores stay in the results, they are just marked, because dropping them would hide the incidents we know least about.

`8_script8validation.py` does both and writes `8_incident_validation.csv`, one row per incident with its score, its stability range and its confidence label.

**Bootstrap.** The headline result is that removing OT monitoring raises stealth by 42.2 points on average. That average comes from 13 incidents, so we check whether a different 13 would give something else. We draw 13 gains at random from our own 13, allowing repeats, and take the average. Doing that 10,000 times gives 10,000 averages, and 95 out of every 100 land between 34.2 and 50.3. So the result does not depend on which incidents we happened to collect. The seed is fixed at 42, so this reproduces exactly.

`9_script9bootstrap.py` does this and writes `9_bootstrap_ci.csv` and `9_bootstrap_gains.csv`.

**Monotonicity.** The four profiles in step e are cumulative, so each one has everything the one below it has, plus more. Buying more monitoring can only ever close a gap, never open one, so no incident's score should rise as you climb. None does. This is a check on the code rather than a finding. If a score ever rose, we would have a bug.

**Weighting sensitivity.** Step 4c turns severity into a number, and it does so by choices we made. We check whether the ranking of the 13 incidents survives making those choices differently. This is step 4g below.

### g. Impact model and weighting sensitivity

Step 4c weights an incident by its severity class alone. Severity class is about the technique, not about what actually happened at the plant, so we add a second term taken from the incident report itself.

**Three physical consequence flags**, recorded per incident in `11_incident_impact_indicators.csv` with a note giving the reason for each:

- **o**, an operator or a safety system had to intervene
- **d**, confirmed physical damage or process disruption
- **c**, documented cascading or multi site effect

The impact weight then has two halves:

```
I_tech = midpoint of the severity class band       (from the technique)
I_phys = average of o, d and c                     (from the incident)
I      = x * I_tech + (1 - x) * I_phys
S      = S_cov * I
```

We set x = 0.5, weighting the two halves equally, and we weight o, d and c equally inside I_phys. Both of those are our choice, not a measurement, which is exactly why they need testing.

**The sensitivity check.** We recompute all 13 scores under seven settings and see whether the order of the incidents changes. Three settings move x to 0.3, 0.5 and 0.7. Four settings keep x at 0.5 and change the balance inside I_phys, weighting o, d and c equally, then putting half the weight on o, then on d, then on c. The baseline setting belongs to both sweeps, which is why the count is seven and not eight. Each ranking is compared to the baseline ranking with a Spearman rank correlation, where 1.0 means the order did not move at all.

The rank correlation stays between 0.82 and 1.0 across all seven settings. Four incidents hold a top five place in all seven, and a fifth holds one in six of the seven, so the head of the table barely moves. The ranking is therefore driven by S_cov, not by how we chose to weight impact.

`11_script11impactweight.py` does this. It reads `5_incident_base_score.csv`, `11_incident_impact_indicators.csv` and `ics-incidents-13.json`, and writes `11_impact_table.csv`, `11_impact_sweep.csv` and `11_impact_ranks.csv`. It also re-derives each incident's severity class from its own technique list and prints it against the class used, so any override is visible rather than buried, and it checks every S it computes against the value printed in the paper.

### h. Stealth Score under each profile

Section e does S_cov under the four profiles. Script 12 does the same for S. It multiplies each incident's S_cov at a profile by that incident's impact factor I.

`12_script12stealthbyprofile.py` does this. It reads `7_ladder_by_incident.csv` and `11_impact_table.csv`, and writes `12_stealth_score_by_profile.csv`, holding S at M1, M2, M3 and M4.

## Which file backs which table in the paper

| Paper | File |
|---|---|
| Table II, coverage stealth across the corpus | `5_incident_base_score.csv`, `6_incident_stealth_score.csv` |
| Table II, the two mean rows | `7_ladder_summary.csv` |
| Table III, monitoring profiles | `7_ladder_summary.csv` |
| Table IV, each incident under four profiles | `7_ladder_by_incident.csv` |
| Table V, validity and robustness summary | `8_incident_validation.csv`, `9_bootstrap_ci.csv`, `11_impact_sweep.csv` |
| Table VIII, leave one out stability | `8_incident_validation.csv` |
| Table X, impact weighting sensitivity | `11_impact_table.csv`, `11_impact_sweep.csv` |
| The 42.2 point headline and its interval | `7_ladder_summary.csv`, `9_bootstrap_ci.csv` |


## Run order

Eleven scripts, run in number order, because each one reads the CSV the one before it wrote. The numbering runs 1 to 12 and skips 10.

```
python3 1_script1tactictechnique.py
python3 2_script2assetspurdue.py
python3 3_script3detectiondatasoruces.py
python3 4_script4coring.py
python3 5_script5incidentscore.py
python3 6_script6impactweight.py
python3 7_script7deploymentprofile.py
python3 8_script8validation.py
python3 9_script9bootstrap.py
python3 11_script11impactweight.py
python3 12_script12stealthbyprofile.py
```

They need python3 with `pandas`, `numpy` and `scipy`.

**Three input files, everything else is generated.** `ics-attack-17.1.json` is MITRE's, unmodified. `ics-incidents-13.json` and `11_incident_impact_indicators.csv` carry our judgement, and are kept as separate readable files so they can be checked or replaced. 
