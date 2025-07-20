import pandas as pd

df = pd.read_csv("E:\\Hunter\\Oppo\\Reconstuff\\nearmecomcn.csv", on_bad_lines='skip')

common = df['Common Name'].dropna().tolist()
match = df['Matching Identities'].dropna().tolist()

all_domains = common + [d for line in match for d in str(line).split('\n')]
# Filter for domains that contain 'com.cn' (case-insensitive)
unique = sorted(set(d for d in all_domains if 'com.cn' in d.lower()))

with open("unique_subdomains.txt", "w") as f:
    f.write('\n'.join(unique))
