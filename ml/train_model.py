import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score


# Load dataset
# Expected CSV columns: subject, body, label
# label convention in dataset: 0 = legitimate ,1 = phishing/spam
df = pd.read_csv("ml_phishing_emails_dataset.csv")

# Remove rows with missing values in critical columns
df = df.dropna(subset=["subject", "body", "label"])

# Create a single text feature by concatenating subject + body
# This is a common baseline approach for email classification                                                 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
df["text"]= df["subject"] + " "+ df["body"]

x = df["text"]
y= df["label"]


# Text vectorization (TF-IDF)
# TF-IDF converts raw text into numeric feature vectors:
#   Terms that appear often in a specific email but not across all emails get higher weight.
#   stop_words="english" removes common words ("the", "and", "is") that usually add noise.
#   max_features limits vocabulary size (controls memory & overfitting)

vectorizer = TfidfVectorizer(stop_words = "english", max_features = 5000)

# Fit vectorizer on the entire dataset text, then transform into a sparse matrix
x_vec = vectorizer.fit_transform(x)


# Train/test split
x_train, x_test, y_train, y_test = train_test_split(x_vec, y, test_size = 0.2 , random_state= 42)  #             !!!!!!!!!!!!!!!!!!!!!!!!




# model training Logistic Regression
# Logistic Regression is a strong baseline for text classification with TF-IDF.
# it is fast to train and run, works very well on sparse high-dimensional data (like TF-IDF)
# produces probabilities (predict_proba) we can map to a 0..100 score
model = LogisticRegression(max_iter = 1000)
model.fit(x_train, y_train)



# Evaluation
# Accuracy = overall percentage of correct predictions
y_pred = model.predict(x_test)
print("Accuracy:", accuracy_score(y_test,y_pred))
print(classification_report(y_test,y_pred))



# Save artifacts for production usage
# We persist both the trained model and the vectorizer.
# The runtime classifier must use the same vectorizer that the model was trained with.
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")



