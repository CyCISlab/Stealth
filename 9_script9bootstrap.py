import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd

B = 10000
SEED = 42


df_lad = pd.read_csv('7_ladder_by_incident.csv')
df_lad['Gain'] = (df_lad['IT only'] - df_lad['Full']).round(1)
df_lad = df_lad.sort_values('Gain', ascending=False)

data = df_lad['Gain'].to_numpy(dtype=float)
n = len(data)

# Resample the n gains with replacement, take the mean, repeat B times.
# 95 of every 100 of those means lie between the 2.5th and 97.5th percentile.
rng = np.random.default_rng(SEED)
boot_means = np.array([rng.choice(data, size=n, replace=True).mean()
                       for _ in range(B)])
lo, hi = np.percentile(boot_means, [2.5, 97.5])

df_out = df_lad[['Incident', 'Full', 'IT only', 'Gain']].copy()
df_out.to_csv('9_bootstrap_gains.csv', index=False)

pd.DataFrame([{
    'Incidents': n,
    'Mean Gain': round(data.mean(), 1),
    'Median Gain': round(float(np.median(data)), 1),
    'CI Low': round(lo, 1),
    'CI High': round(hi, 1),
    'Resamples': B,
    'Seed': SEED
}]).to_csv('9_bootstrap_ci.csv', index=False)

print("9_Script 9 Completed")
print(f"Incidents: {n} | Resamples: {B:,} | Seed: {SEED}")
print(f"Mean gain   : {data.mean():.1f}")
print(f"Median gain : {np.median(data):.1f}")
print(f"95% CI      : [{lo:.1f}, {hi:.1f}]")
print()
print(df_out.to_string(index=False))
