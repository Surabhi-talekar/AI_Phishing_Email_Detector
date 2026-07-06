from flask import Flask, render_template, request
import joblib
import re

# Create Flask app
app = Flask(__name__)

# Load AI model
model = joblib.load("model/phishing_model.pkl")
vectorizer = joblib.load("model/vectorizer.pkl")
# ----------------------------
# Suspicious Keyword Categories
# ----------------------------

URGENT_WORDS = [
    "urgent",
    "immediately",
    "asap",
    "important",
    "warning",
    "alert"
]

BANKING_WORDS = [
    "bank",
    "account",
    "payment",
    "credit",
    "debit",
    "transaction"
]

CREDENTIAL_WORDS = [
    "password",
    "login",
    "verify",
    "otp",
    "pin",
    "username"
]

REWARD_WORDS = [
    "winner",
    "won",
    "gift",
    "free",
    "reward",
    "prize"
]


# Text cleaning function
def clean_text(text):
    text = str(text)
    text = text.lower()

    text = re.sub(r'http\S+|www\S+', '', text)
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()

    return text 

# ----------------------------
# Threat Detection Function
# ----------------------------
def detect_threats(email):
    threats = []

    email = email.lower()

    if any(word in email for word in URGENT_WORDS):
        threats.append("⚠ Urgent language detected")

    if any(word in email for word in BANKING_WORDS):
        threats.append("🏦 Banking-related keywords detected")

    if any(word in email for word in CREDENTIAL_WORDS):
        threats.append("🔐 Credential-related keywords detected")

    if any(word in email for word in REWARD_WORDS):
        threats.append("🎁 Prize / Reward language detected")

    return threats
# ----------------------------
# URL Extraction
# ----------------------------
def extract_urls(email):
    pattern = r'https?://[^\s]+'
    urls = re.findall(pattern, email)
    return urls

  
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    email = request.form["email"]
    
    threats = detect_threats(email)
    urls = extract_urls(email)

    print("URLs Found:", urls)

    print(threats)

    cleaned = clean_text(email)

    vector = vectorizer.transform([cleaned])

    prediction = model.predict(vector)[0]

    probability = model.predict_proba(vector)[0]

    confidence = max(probability) * 100

    if prediction == 1:
        result = "🚨 Phishing / Spam Email"
    else:
        result = "✅ Safe Email"

    return render_template(
    "index.html",
    prediction=result,
    confidence=round(confidence, 2),
    email=email,
    threats=threats,
    urls=urls
)


if __name__ == "__main__":
    app.run(debug=True)