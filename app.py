from flask import Flask, render_template, request, redirect, url_for, session,send_file
import joblib
import re
import os
from datetime import datetime
from reportlab.pdfgen import canvas
import io

# Create Flask app
app = Flask(__name__)

app.secret_key = "cybershield_secret_key"

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

ATTACHMENT_WORDS = [
    "attachment",
    "attached",
    "download",
    "invoice",
    "document",
    "pdf",
    "zip",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "exe"
]

TRUSTED_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "paypal.com",
    "amazon.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com"
]
TRUSTED_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "paypal.com",
    "amazon.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com"
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
# Attachment Detection
# ----------------------------
def detect_attachments(email):

    attachments = []

    email = email.lower()

    for word in ATTACHMENT_WORDS:
        if word in email:
            attachments.append(word)

    return list(set(attachments))
def analyze_sender(email):

    pattern = r'[\w\.-]+@[\w\.-]+'

    match = re.search(pattern, email)

    if not match:
        return None

    sender = match.group()

    domain = sender.split("@")[1]

    if domain in TRUSTED_DOMAINS:
        status = "✅ Trusted Domain"

    else:
        status = "⚠ Unknown Domain"

    return {
        "sender": sender,
        "domain": domain,
        "status": status
    }

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

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("index.html")
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "cyber123":

            session["user"] = username

            return redirect(url_for("home"))

        else:

            return render_template(
                "login.html",
                error="Invalid Username or Password"
            )

    return render_template("login.html")


@app.route("/predict", methods=["POST"])
def predict():

    email = request.form.get("email", "")

    uploaded_file = request.files.get("email_file")

    # If a file is uploaded, use its contents
    if uploaded_file and uploaded_file.filename != "":
        email = uploaded_file.read().decode("utf-8")
    if not email.strip():

     return render_template(
        "index.html",
        error="⚠ Please paste an email or upload a .txt file."
    )

    # -----------------------
    # Analyze Email
    # -----------------------

    threats = detect_threats(email)
    urls = extract_urls(email)

    url_analysis = analyze_urls(urls)
    highlighted_email = highlight_text(email)
    attachments = detect_attachments(email)
    sender_info = analyze_sender(email)

    cleaned = clean_text(email)

    vector = vectorizer.transform([cleaned])

    prediction = model.predict(vector)[0]

    probability = model.predict_proba(vector)[0]

    confidence = max(probability) * 100

    if prediction == 1:
        result = "🚨 Phishing / Spam Email"
    else:
        result = "✅ Safe Email"
    session["prediction"] = result
    session["confidence"] = round(confidence, 2)
    session["threats"] = threats
    session["urls"] = urls
    session["attachments"] = attachments

    return render_template(
        "index.html",
        prediction=result,
        confidence=round(confidence, 2),
        email=email,
        threats=threats,
        urls=urls,
        url_analysis=url_analysis,
        highlighted_email=highlighted_email,
        attachments=attachments,
        sender_info=sender_info
    )  
@app.route("/download_report")
def download_report():

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer)

    pdf.setTitle("CyberShield AI Report")

# -----------------------------
# Header
# -----------------------------

    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawString(50, 810, "🛡 CyberShield AI")

    pdf.setFont("Helvetica", 14)
    pdf.drawString(50, 790, "AI Powered Email Threat Analysis Report")

# Horizontal line
    pdf.line(50, 780, 550, 780)

    pdf.setFont("Helvetica", 12)
    now = datetime.now()

    date = now.strftime("%d %B %Y")
    time = now.strftime("%I:%M %p")

    y = 750

    pdf.drawString(50, y, f"Date : {date}")

    pdf.drawString(350, y, f"Time : {time}")

    y -= 30

     # -----------------------------
# Prediction
# -----------------------------

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Prediction")

    y -= 20

    pdf.setFont("Helvetica", 12)
    pdf.drawString(70, y, session.get("prediction", "N/A"))

    y -= 30

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Confidence Score")

    y -= 20

    pdf.setFont("Helvetica", 12)
    pdf.drawString(70, y, f"{session.get('confidence', 'N/A')} %")

    y -= 30

# Horizontal line
    pdf.line(50, y, 550, y)

    y -= 25

    pdf.drawString(50, y, "Threats:")
    y -= 20

    threats = session.get("threats", [])

    if threats:
        for threat in threats:
            pdf.drawString(70, y, f"- {threat}")
            y -= 20
    else:
        pdf.drawString(70, y, "No threats detected.")
        y -= 20

    y -= 10

    pdf.drawString(50, y, "URLs:")
    y -= 20

    urls = session.get("urls", [])

    if urls:
        for url in urls:
            pdf.drawString(70, y, url)
            y -= 20
    else:
        pdf.drawString(70, y, "No URLs found.")
        y -= 20

    y -= 10

    pdf.drawString(50, y, "Attachments:")
    y -= 20

    attachments = session.get("attachments", [])

    if attachments:
        pdf.drawString(70, y, ", ".join(attachments))
    else:
        pdf.drawString(70, y, "None")

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="CyberShield_Report.pdf",
        mimetype="application/pdf"
    )
   

   


if __name__ == "__main__":
    app.run(debug=True)