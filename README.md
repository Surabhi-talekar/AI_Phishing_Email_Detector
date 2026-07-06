# 🛡️ CyberShield AI - Phishing Email Detection System

CyberShield AI is an AI-powered phishing email detection system built using **Python, Flask, and Machine Learning**. The application analyzes email content, predicts whether it is phishing or safe, detects suspicious indicators, extracts URLs, and performs URL security analysis.

---

## 📌 Features

- 🤖 AI-based phishing email detection
- 📊 Confidence score prediction
- ⚠️ Threat analysis using suspicious keywords
- 💡 Security recommendations
- 🌐 URL extraction from email content
- 🔍 URL security analysis
- 🔒 Detects HTTP and HTTPS links
- 🚨 Identifies suspicious URL keywords
- 🎨 Modern and responsive user interface

---

## 🖥️ Technologies Used

- Python 3.x
- Flask
- Scikit-learn
- Pandas
- NumPy
- Joblib
- HTML
- CSS
- Regular Expressions (Regex)

---

## 📂 Project Structure

```
AI_Phishing_Email_Detector/
│
├── dataset/
│   └── phishing_email.csv
│
├── model/
│   ├── phishing_model.pkl
│   └── vectorizer.pkl
│
├── templates/
│   └── index.html
│
├── train_model.py
├── app.py
├── requirements.txt
├── README.md
└── venv/
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/CyberShield-AI.git
```

---

### 2. Open the Project

```bash
cd CyberShield-AI
```

---

### 3. Create Virtual Environment

```bash
python -m venv venv
```

---

### 4. Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux / macOS

```bash
source venv/bin/activate
```

---

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 6. Train the Model

```bash
python train_model.py
```

This will generate:

- phishing_model.pkl
- vectorizer.pkl

inside the **model** folder.

---

### 7. Run the Application

```bash
python app.py
```

Open your browser and visit

```
http://127.0.0.1:5000
```

---

## 📖 How It Works

1. User pastes an email.
2. Email text is cleaned using Regex.
3. Text is converted into numerical vectors using TF-IDF.
4. Logistic Regression predicts whether the email is phishing or safe.
5. Threat keywords are detected.
6. URLs are extracted.
7. Each URL is analyzed for:
   - HTTP/HTTPS
   - Suspicious keywords
   - Risk Level
8. Results are displayed on the dashboard.

---

## 🚨 Threat Detection Categories

CyberShield AI detects:

- Urgent language
- Banking keywords
- Credential-related keywords
- Reward and prize scams

---

## 🌐 URL Security Analysis

The application analyzes every extracted URL.

Example:

```
URL:
http://fake-bank-login.com

Security:
❌ HTTP (Not Secure)

Risk:
🔴 High

Suspicious Keywords:
login, bank
```

---

## 📸 Screenshots

### Home Page

Paste email content into the analyzer.

### Analysis Result

Displays:

- AI Prediction
- Confidence Score
- Threat Analysis
- Recommendation
- URL Security Analysis

---

## 📈 Future Improvements

- Risk Score Meter
- File Upload (.txt/.eml)
- Email Header Analysis
- VirusTotal API Integration
- Dashboard with Analytics
- Scan History using SQLite
- PDF Report Generation
- User Authentication
- Dark/Light Theme
- Email Attachment Scanner

---

## 🎯 Learning Outcomes

This project demonstrates:

- Machine Learning
- Natural Language Processing
- Flask Web Development
- Cybersecurity Fundamentals
- URL Threat Detection
- Data Preprocessing
- Model Deployment

---

## 👩‍💻 Author

**Surabhi Talekar**

Cybersecurity & AI Enthusiast

---

## 📜 License

This project is developed for educational and portfolio purposes.
