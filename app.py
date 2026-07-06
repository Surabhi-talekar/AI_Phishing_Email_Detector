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

# ----------------------------
# Suspicious URL Keywords
# ----------------------------

SUSPICIOUS_URL_WORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "paypal",
    "account",
    "signin",
    "password",
    "confirm"
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
# Highlight Suspicious Words
# ----------------------------

def highlight_text(email):

    suspicious_words = (
        URGENT_WORDS
        + BANKING_WORDS
        + CREDENTIAL_WORDS
        + REWARD_WORDS
    )

    highlighted = email

    for word in suspicious_words:

        pattern = re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE)

        highlighted = pattern.sub(
            lambda match: f"<mark>{match.group(0)}</mark>",
            highlighted
        )

    return highlighted
# ----------------------------
# URL Extraction
# ----------------------------
def extract_urls(email):
    pattern = r'https?://[^\s]+'
    urls = re.findall(pattern, email)
    return urls
# ----------------------------
# URL Risk Analysis
# ----------------------------

def analyze_urls(urls):

    analysis = []

    for url in urls:

        info = {}

        info["url"] = url

        # HTTPS or HTTP
        if url.startswith("https://"):
            info["security"] = "✅ HTTPS (Secure)"
        else:
            info["security"] = "❌ HTTP (Not Secure)"

        # Suspicious keywords
        found_keywords = []

        lower_url = url.lower()

        for word in SUSPICIOUS_URL_WORDS:

            if word in lower_url:
                found_keywords.append(word)

        info["keywords"] = found_keywords

        # Risk Level
        if info["security"].startswith("❌") or len(found_keywords) >= 2:
            info["risk"] = "🔴 High"

        elif len(found_keywords) == 1:
            info["risk"] = "🟡 Medium"

        else:
            info["risk"] = "🟢 Low"

        analysis.append(info)

    return analysis

  
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    email = request.form["email"]
    
    threats = detect_threats(email)
    urls = extract_urls(email)
    
    url_analysis = analyze_urls(urls)
    highlighted_email = highlight_text(email)

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
        url_analysis = analyze_urls(urls)
        print(url_analysis)
    return render_template(
    "index.html",
    prediction=result,
    confidence=round(confidence, 2),
    email=email,
    threats=threats,
    urls=urls,
    url_analysis=url_analysis,
    highlighted_email=highlighted_email
    
    
)    
   

   


if __name__ == "__main__":
    app.run(debug=True)