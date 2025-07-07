import pandas as pd

df = pd.read_csv("E:\\Hunter\\Oppo\\Reconstuff2025-07-07_oppomobilecom.csv", on_bad_lines='skip')

common = df['Common Name'].dropna().tolist()
match = df['Matching Identities'].dropna().tolist()

all_domains = common + [d for line in match for d in line.split('\n')]
unique = sorted(set(d for d in all_domains if 'oppomobile.com' in d.lower()))

with open("unique_subdomains.txt", "w") as f:
    f.write('\n'.join(unique))
