import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

df = pd.read_csv("ml_phishing_emails_dataset.csv")

df = df.dropna(subset=["subject", "body", "label"])
df["text"]= df["subject"] + " "+ df["body"]

x = df["text"]
y= df["label"]

vectorizer = TfidfVectorizer(stop_words = "english", max_features = 5000)

x_vec = vectorizer.fit_transform(x)

x_train, x_test, y_train, y_test = train_test_split(x_vec, y, test_size = 0.2 , random_state= 42)

model = LogisticRegression(max_iter = 1000)
model.fit(x_train, y_train)

y_pred = model.predict(x_test)
print("Accuracy:", accuracy_score(y_test,y_pred))
print(classification_report(y_test,y_pred))

joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")



