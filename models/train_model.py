import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load the features
features = pd.read_csv('network_traffic_features.csv')

# Initialize the Isolation Forest model
clf = IsolationForest(contamination=0.01, random_state=42)

# Train the model
clf.fit(features)

# Save the trained model to a file
joblib.dump(clf, 'isolation_forest_model.pkl')

print("Model trained and saved as isolation_forest_model.pkl")
