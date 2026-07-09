# 🛡 CyberShield AI

An AI-powered Email Threat Analyzer built using **Flask** and **Machine Learning** that detects phishing emails and provides detailed threat analysis, URL inspection, sender analysis, attachment detection, and downloadable PDF reports.

---

## 📌 Project Overview

CyberShield AI is a cybersecurity web application that helps users identify phishing and spam emails using Machine Learning. The application analyzes email content, highlights suspicious keywords, inspects URLs, detects attachment-related threats, and generates a detailed PDF report.

---

## ✨ Features

- 🔐 User Login Authentication
- 🤖 AI-based Phishing Email Detection
- 📊 Confidence Score
- ⚠ Threat Analysis
- 🌐 URL Extraction & Security Analysis
- 📧 Sender Domain Analysis
- 📎 Attachment Detection
- 📝 Suspicious Keyword Highlighting
- 📄 Download Analysis Report as PDF
- 📂 Email File (.txt) Upload Support
- 🎨 Responsive and User-Friendly Interface

---

## 🛠 Technologies Used

### Frontend
- HTML5
- CSS3

### Backend
- Flask (Python)

### Machine Learning
- Scikit-learn
- TF-IDF Vectorizer
- Logistic Regression

### Libraries
- Joblib
- ReportLab
- Regular Expressions (re)

---

## 📂 Project Structure

```
CyberShield-AI/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── model/
│   ├── phishing_model.pkl
│   └── vectorizer.pkl
│
├── templates/
│   ├── login.html
│   └── index.html
│
├── static/
│   ├── style.css
│   └── logo.png
│
├── screenshots/
│
└── dataset/
    └── phishing_email.csv
```

---

## ⚙ Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/CyberShield-AI.git
```

### Move into Project Folder

```bash
cd CyberShield-AI
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

---

## 🔄 Workflow

1. User logs into the application.
2. User enters email text or uploads a `.txt` file.
3. Email is preprocessed.
4. TF-IDF converts text into numerical features.
5. Logistic Regression predicts whether the email is Safe or Phishing.
6. Additional security checks are performed:
   - Threat Detection
   - URL Analysis
   - Sender Analysis
   - Attachment Detection
7. Results are displayed.
8. User can download a PDF report.

---

## 📊 Machine Learning Model

| Model | Logistic Regression |
|--------|---------------------|
| Feature Extraction | TF-IDF Vectorizer |
| Language | Python |
| Library | Scikit-learn |

---

## 📸 Screenshots

## Login Page

![alt text](<login page cybershield.png>)


## Home Page

![alt text](<homepage cybershield.png>)

## Phishing Detection

![alt text](<phishing detection.png>)
![alt text](<result pdf.png>)
```

---

## 📄 PDF Report

The application can generate a professional PDF report containing:

- Prediction Result
- Confidence Score
- Threat Analysis
- URL Analysis
- Attachment Analysis
- Recommendation
- Date & Time

---

## 🔮 Future Scope

- Support for .eml email files
- Real-time Email Monitoring
- VirusTotal API Integration
- Dashboard with Analysis History
- Risk Meter Visualization
- Email Header Analysis

---

## 👩‍💻 Author

**Surabhi Talekar**

Bachelor of Engineering (Information Technology)

---

## 📜 License

This project is developed for educational and academic purposes.

---

## ⭐ If you like this project

Give it a ⭐ on GitHub.