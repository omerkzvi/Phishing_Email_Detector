Phishing Email Detection and Gmail Add-on

A phishing detection system that combines:
Rule-based heuristics
ML model - Logistic Regression

The backend is a Flask API  
The frontend is a Gmail Add-on that scans the currently opened email on demand.



What This Project Does

When the user clicks "Scan for Phishing" in Gmail:
1. The Add-on extracts the email (From/Reply-To/Subject + body + HTML).
2. Runs a local quick URL pre-check in Apps Script for obvious high-risk indicators.
3. Sends the email payload to the backend endpoint: `POST /scan-email`
4. The backend:
   - Parses URLs + sender domain
   - Runs heuristics
   - Runs ML prediction (if artifacts exist)
   - Produces a final score + classification + reasons + confidence metadata
5.The Add-on displays the result in a clean card UI.



How Detection Works (Backend)

 1) Parsing & Extraction (`app/parser.py`)
Extracts structured data from the email:
sender_domain ,Links from:

2) Heuristics Engine (`app/heuristics.py`)
Deterministic rules that return explainable results.

3) ML Model  ('ml/ml_classifier.py')
Logistic Regression 

4) Final Scoring + Critical Floors (service/phishing_service.py)

5) Classification (Thresholds)
score >= 80 → Phishing (High)
score >= 50 → Suspicious (Medium)
else → Safe (Low)

6) Confidence Metadata
Returned for transparency:
Decision confidence: how far we are from the relevant threshold
Evidence confidence: whether ML is available + ML confidence
Overall confidence: average of decision & evidence


Setup & Installation

1) Python Backend
Requirements: Python 3.10+

Install deps:
pip install -r requirements.txt

requirements.txt:
flask
flask-cors
pydantic
scikit-learn
pandas
joblib
beautifulsoup4

Run server:
python controller/phishing_controller.py

2) Train the ML Model (Optional)


Gmail Add-on Setup (Google Apps Script)

Create a new Apps Script project (script.google.com)
Paste Gmail add on/appsscript into the editor
Enable Advanced Gmail Service (Gmail API)
In Script Properties, set:
PHISHING_BACKEND_URL = https://phishing-email-detector-inv6.onrender.com/scan-email
Deploy → Test deployments → Install

Usage:
Open an email → click the add-on → press Scan for Phishing

Limitations

Heuristics are lightweight → may produce false positives/negatives
ML performance depends on dataset quality and domain similarity
No authentication/rate-limiting by default

Future Improvements
Add rate limiting (e.g., requests per minute per IP) to protect the API from abuse
Add user authentication
Adjust ML vs heuristics weights
Improve training with class balancing to reduce bias toward one label.


