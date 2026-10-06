"""!!! DEMO / SMOKE-TEST DATA ONLY - NOT A REAL DATASET !!!
Generates synthetic URLs so the pipeline can be tested without internet.
NEVER report metrics from this file in the final report."""
import random, os
import pandas as pd
random.seed(1)
words = ["shop", "news", "blog", "mail", "cloud", "tech", "food", "travel", "learn", "game", "photo", "bank"]
tlds = ["com", "org", "net", "in", "io"]
bad_tlds = ["xyz", "top", "tk", "click", "icu"]
kw = ["login", "verify", "secure", "account", "update", "confirm"]
rows = []
for _ in range(1500):
    d = random.choice(words) + random.choice(words)
    rows.append((f"https://www.{d}.{random.choice(tlds)}/" + random.choice(["", "about", "products/item"]), 0))
for _ in range(1500):
    brand = random.choice(["paypal", "sbi", "amazon", "google", "netflix"])
    k = random.sample(kw, 2)
    host = random.choice([f"{brand}-{k[0]}.{random.choice(bad_tlds)}",
                          f"{k[0]}.{brand}.{k[1]}-{random.randint(10,99)}.{random.choice(bad_tlds)}",
                          f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"])
    rows.append((f"http://{host}/{k[1]}/{random.randint(1000,99999)}.php?id={random.randint(1,999)}", 1))
pd.DataFrame(rows, columns=["url", "label"]).sample(frac=1, random_state=1).to_csv(
    os.path.join(os.path.dirname(__file__), "..", "data", "demo_dataset_SYNTHETIC.csv"), index=False)
print("wrote demo_dataset_SYNTHETIC.csv")
