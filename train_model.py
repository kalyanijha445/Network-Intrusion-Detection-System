import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

# Load dataset
df = pd.read_csv("network_data.csv")

# Encode protocol
protocol_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
df["protocol"] = df["protocol"].map(protocol_map)

# Binary label encoding
df["label"] = df["label"].apply(lambda x: "Normal" if x == "Normal" else "Intrusion")

# Features and labels
X = df[["duration", "protocol", "src_bytes", "dst_bytes"]]
y = df["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model
with open("nids_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained and saved as nids_model.pkl")
