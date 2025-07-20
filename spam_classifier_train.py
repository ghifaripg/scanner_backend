import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import gensim.downloader as api
import joblib
import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import nltk

# Download NLTK resources
nltk.download('punkt')
nltk.download('stopwords')

# Load only necessary columns
df = pd.read_csv("email.csv", usecols=['subject', 'body', 'label'])

# Drop rows with missing labels
df = df.dropna(subset=['label'])

# Combine subject and body into one text field
df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')

# Preprocess text
stop_words = set(stopwords.words('english'))

def preprocess(text):
    text = re.sub(r'\W+', ' ', text.lower())  # Lowercase and remove non-word characters
    words = word_tokenize(text)
    return [w for w in words if w not in stop_words]

df['tokens'] = df['text'].apply(preprocess)

# Load pretrained Word2Vec
print("⏬ Loading Word2Vec model (Google News)...")
w2v_model = api.load('word2vec-google-news-300')  # Downloads ~1.6GB on first run
print("✅ Word2Vec model loaded.")

# Vectorize emails using averaged Word2Vec vectors
def vectorize(tokens):
    vectors = [w2v_model[w] for w in tokens if w in w2v_model]
    if len(vectors) == 0:
        return np.zeros(300)
    return np.mean(vectors, axis=0)

df['vector'] = df['tokens'].apply(vectorize)

# Features and labels
X = np.vstack(df['vector'].values)

# Encode labels (handles string categories)
le = LabelEncoder()
y = le.fit_transform(df['label'])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train SVM
clf = SVC(kernel='linear', probability=True, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print("=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=[str(cls) for cls in le.classes_]))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

# Save model and label encoder
joblib.dump(clf, "svm_word2vec_model.pkl")
joblib.dump(w2v_model, "word2vec_model.pkl")
joblib.dump(le, "label_encoder.pkl")

print("✅ SVM + Word2Vec model and label encoder saved.")