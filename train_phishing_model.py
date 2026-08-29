import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# ==========================================
# CYBERSENTINEL - ML TRAINING PIPELINE
# ==========================================

# 1. LOAD THE DATASET
# We train the model on a massive dataset of SMS, Emails, and URLs.
# Dataset contains two columns: 'text' (the message) and 'label' (1 = Phishing/Spam, 0 = Safe)
print("Loading cybersecurity dataset...")
data = {
    'text': [
        "URGENT: Your bank account has been blocked. Click here to verify.",
        "Hey, are we still meeting for lunch tomorrow?",
        "Congratulations! You've won a $1000 gift card. Share your OTP to claim.",
        "Please review the attached project report before the meeting.",
        "Action Required: Update your KYC details immediately at http://fake-bank-update.com"
    ],
    'label': [1, 0, 1, 0, 1] 
}
df = pd.DataFrame(data)

# 2. FEATURE EXTRACTION (Text to Numbers)
# Machine Learning models can't read text, they only understand numbers.
# We use TF-IDF (Term Frequency-Inverse Document Frequency) to convert words into numerical importance scores.
print("Applying TF-IDF Vectorization...")
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X = vectorizer.fit_transform(df['text'])
y = df['label']

# 3. TRAIN/TEST SPLIT
# We split our data: 80% to train the model, 20% to test it on unseen data.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. TRAIN THE MACHINE LEARNING MODEL
# We use a Random Forest Classifier because it creates multiple "decision trees" 
# to vote on whether a message is malicious, making it highly accurate for text.
print("Training the Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. EVALUATE THE MODEL
print("Evaluating model performance on test data...")
predictions = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%\n")
print("Classification Report:")
print(classification_report(y_test, predictions))

# 6. EXPORT THE MODEL
# We save the trained model so it can be loaded into a Python API (like Flask/FastAPI)
# and used by our React frontend.
print("Saving model weights...")
joblib.dump(model, 'phishing_detection_model.pkl')
joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')

print("Training Complete! The AI model is ready for CyberSentinel.")
