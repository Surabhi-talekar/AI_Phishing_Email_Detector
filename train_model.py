# Import required libraries
import pandas as pd
import re
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# ==========================
# Load Dataset
# ==========================
data = pd.read_csv("dataset/emails.csv")

# ==========================
# Clean Text Function
# ==========================
def clean_text(text):
    text = str(text)
    text = text.lower()

    # Remove URLs
    text = re.sub(r'http\S+|www\S+', '', text)

    # Remove email addresses
    text = re.sub(r'\S+@\S+', '', text)

    # Remove numbers
    text = re.sub(r'\d+', '', text)

    # Remove punctuation
    text = re.sub(r'[^a-zA-Z\s]', '', text)

    # Remove extra spaces
    text = re.sub(r'\s+', ' ', text).strip()

    return text

# Clean the email text
data["clean_text"] = data["text"].apply(clean_text)

# ==========================
# Features and Labels
# ==========================
X = data["clean_text"]
y = data["spam"]

# ==========================
# Convert Text to Numbers
# ==========================
vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(X)

# ==========================
# Split Dataset
# ==========================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# ==========================
# Train Model
# ==========================
model = LogisticRegression()

model.fit(X_train, y_train)

# ==========================
# Predictions
# ==========================
y_pred = model.predict(X_test)

# ==========================
# Accuracy
# ==========================
accuracy = accuracy_score(y_test, y_pred)

print("\n==============================")
print("MODEL ACCURACY")
print("==============================")

print(f"Accuracy: {accuracy * 100:.2f}%")

print("\nClassification Report\n")
print(classification_report(y_test, y_pred))

# ==========================
# Save Model
# ==========================
joblib.dump(model, "model/phishing_model.pkl")
joblib.dump(vectorizer, "model/vectorizer.pkl")

print("\nModel saved successfully!")
print("Vectorizer saved successfully!")