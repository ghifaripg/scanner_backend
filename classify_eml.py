import email
from email import policy
from email.parser import BytesParser
import joblib
import re
import numpy as np
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import nltk
import sys

# One-time downloads
nltk.download('punkt')
nltk.download('stopwords')

# Load models
clf = joblib.load("svm_word2vec_model.pkl")
w2v_model = joblib.load("word2vec_model.pkl")

# Preprocessing function
stop_words = set(stopwords.words('english'))
def preprocess(text):
    text = re.sub(r'\W+', ' ', text.lower())
    words = word_tokenize(text)
    return [w for w in words if w not in stop_words]

# Vectorization function
def vectorize(tokens):
    vectors = [w2v_model[w] for w in tokens if w in w2v_model]
    if not vectors:
        return np.zeros(300)
    return np.mean(vectors, axis=0)

# Extract subject + body from .eml
def extract_eml_text(eml_path):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg['subject'] or ''
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    return subject + ' ' + body

# Run classification
def classify_eml(eml_path):
    text = extract_eml_text(eml_path)
    tokens = preprocess(text)
    vec = vectorize(tokens).reshape(1, -1)
    prediction = clf.predict(vec)[0]
    proba = clf.predict_proba(vec)[0][int(prediction)]
    return prediction, proba

# CLI usage
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python classify_eml.py path/to/email.eml")
        sys.exit(1)

    path = sys.argv[1]
    label, confidence = classify_eml(path)

    result = "Phishing/Spam" if label == 1 else "Legitimate"
    print(f"\n📧 Prediction: {result}")
    print(f"📈 Confidence: {confidence:.2f}")
