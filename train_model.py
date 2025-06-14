import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

# Step 1: Load the new dataset
df = pd.read_csv("phishing.csv")

# Step 2: Separate features and target label
X = df.drop("phishing", axis=1)
y = df["phishing"]

# Step 3: Split the data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Step 4: Train the model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Step 5: Evaluate it (just to check)
accuracy = accuracy_score(y_test, model.predict(X_test))
print(f"✅ Model trained! Accuracy: {accuracy * 100:.2f}%")

# Step 6: Save the model
with open("phishing_model_final.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model saved as phishing_model_final.pkl")
