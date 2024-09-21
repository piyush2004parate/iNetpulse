import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load the data from CSV
df = pd.read_csv('network_traffic_data.csv')

# Encode protocol as numeric
encoder = LabelEncoder()
df['protocol_encoded'] = encoder.fit_transform(df['protocol'])

# Select features for training
features = df[['len', 'ttl', 'protocol_encoded']]

# Fill any missing values with zeros
features = features.fillna(0)

# Save the features for model training
features.to_csv('network_traffic_features.csv', index=False)
print("Features saved to network_traffic_features.csv")
