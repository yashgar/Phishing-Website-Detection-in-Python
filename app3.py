from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
import joblib, os, tldextract, ssl, socket
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import VarianceThreshold
from scipy.sparse import hstack
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

CSV_FILE = "dataset2phishing.csv"
CNN_MODEL_FILE = "cnn_url_model.h5"
CNN_TOKENIZER_FILE = "cnn_tokenizer.joblib"
RF_XGB_MODEL_FILE = "rf_xgb_model.joblib"

app = Flask(__name__)
max_len = 200

def ssl_certificate_info(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return "No SSL certificate present"
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                return {
                    'Issued To': subject.get('commonName', 'Unknown'),
                    'Issued By': issuer.get('commonName', 'Unknown'),
                    'Valid From': cert.get('notBefore', 'Unknown'),
                    'Valid To': cert.get('notAfter', 'Unknown')
                }
    except:
        return "No SSL certificate present"

def extract_features(url):
    ext = tldextract.extract(url)
    return [
        len(url), len(ext.domain), len(ext.suffix),
        url.count('.'), url.count('-'), url.count('_'),
        url.count('/'), url.count('?'),
        sum(c.isdigit() for c in url),
        int(url.startswith("https")),
        int('@' in url),
        int(ext.suffix in ["ru", "cn", "xyz", "top", "tk"])
    ]

def train_cnn():
    print("[INFO] Training CNN model...")
    df = pd.read_csv(CSV_FILE, encoding='utf-8-sig').dropna()
    df.rename(columns=lambda x: x.strip().lower().replace("ï»¿", ""), inplace=True)
    df = df[df['label'].isin([0, 1])].copy()
    df.dropna(subset=['url', 'label'], inplace=True)

    y = df['label']
    tokenizer = Tokenizer(char_level=True)
    tokenizer.fit_on_texts(df['url'])
    X_seq = tokenizer.texts_to_sequences(df['url'])
    X_pad = pad_sequences(X_seq, maxlen=max_len, padding='post', truncating='post')

    cnn = Sequential([
        Embedding(len(tokenizer.word_index) + 1, 64, input_length=max_len),
        Bidirectional(LSTM(64)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])
    cnn.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    cnn.fit(X_pad, y, epochs=10, batch_size=128, validation_split=0.2, verbose=1)

    cnn.save(CNN_MODEL_FILE)
    joblib.dump(tokenizer, CNN_TOKENIZER_FILE)
    print(f"[INFO] CNN trained on {len(df)} URLs.")
    return cnn, tokenizer

def train_rf_xgb():
    print("[INFO] Training RF + XGB models...")
    df = pd.read_csv(CSV_FILE, encoding='utf-8-sig').dropna()
    df.rename(columns=lambda x: x.strip().lower().replace("ï»¿", ""), inplace=True)
    df = df[df['label'].isin([0, 1])].copy()
    df.dropna(subset=['url', 'label'], inplace=True)

    y = df['label']
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=5000)
    tfidf_X = vectorizer.fit_transform(df['url'])

    manual_features = np.array([extract_features(u) for u in df['url']])
    selector = VarianceThreshold(threshold=0.0)
    manual_features = selector.fit_transform(manual_features)

    X = hstack([tfidf_X, manual_features])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    rf = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
    xgb = XGBClassifier(n_estimators=300, max_depth=7, learning_rate=0.05,subsample=0.8, colsample_bytree=0.8, eval_metric='logloss', random_state=42)
    rf.fit(X_train, y_train)
    xgb.fit(X_train, y_train)

    joblib.dump((rf, xgb, vectorizer, selector), RF_XGB_MODEL_FILE)
    print(f"[INFO] RF + XGB trained on {len(df)} URLs.")
    return rf, xgb, vectorizer, selector

cnn_model, cnn_tokenizer = (load_model(CNN_MODEL_FILE), joblib.load(CNN_TOKENIZER_FILE)) \
    if os.path.exists(CNN_MODEL_FILE) and os.path.exists(CNN_TOKENIZER_FILE) else train_cnn()

rf_model, xgb_model, vectorizer, selector = joblib.load(RF_XGB_MODEL_FILE) \
    if os.path.exists(RF_XGB_MODEL_FILE) else train_rf_xgb()

def hybrid_predict(url):

    seq = cnn_tokenizer.texts_to_sequences([url])
    seq_pad = pad_sequences(seq, maxlen=max_len, padding='post', truncating='post')
    cnn_proba = cnn_model.predict(seq_pad, verbose=0)[0][0]

    tfidf_input = vectorizer.transform([url])
    manual_input = np.array([extract_features(url)])
    manual_input = selector.transform(manual_input)
    X_input = hstack([tfidf_input, manual_input])
    rf_proba = rf_model.predict_proba(X_input)[0][1]
    xgb_proba = xgb_model.predict_proba(X_input)[0][1]

    final_proba = (cnn_proba + rf_proba + xgb_proba) / 3
    return final_proba

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        data = request.get_json()
        url = data['url'].strip()

        proba = hybrid_predict(url)
        result = "LEGITIMATE" if proba > 0.65 else "PHISHING"
        accuracy = round(max(proba, 1 - proba) * 100, 2)
        ssl_info = ssl_certificate_info(url) if urlparse(url).scheme == 'https' else "No SSL certificate present"

        return jsonify({"result": result, "accuracy": accuracy, "ssl_info": ssl_info})

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
