# Phishing Email Detection Model

A machine learning-based system to classify emails as **Phishing** or **Safe** using Scikit-learn and advanced feature engineering.

## 📋 Overview

This project implements a Random Forest classifier that analyzes email content to detect phishing attempts. It extracts multiple feature categories and achieves high accuracy in email classification.

### Key Features

- **URL Analysis**: Detects suspicious URLs, shortened links, and IP-based addresses
- **Keyword Detection**: Identifies phishing-related keywords and urgency indicators
- **Structural Analysis**: Analyzes email format patterns (case ratios, punctuation, etc.)
- **Random Forest Classification**: Ensemble learning for robust predictions
- **Performance Metrics**: Confusion matrix, accuracy, ROC-AUC, and classification reports
- **Feature Importance Analysis**: Identifies which features are most predictive

## 🏗️ Architecture

### Feature Categories

1. **URL Features** (4 features)
   - `url_count`: Number of URLs in email
   - `suspicious_url_count`: Count of suspicious URLs
   - `ip_based_url`: IP-based address detection
   - `short_url`: Shortened URL detection

2. **Keyword Features** (5 features)
   - `urgent_keywords`: Urgency language count
   - `suspicious_keywords`: Phishing-related keywords
   - `financial_keywords`: Banking/payment terms
   - `verification_keywords`: Authentication requests
   - `exclamation_count`: Excessive punctuation

3. **Structural Features** (5 features)
   - `text_length`: Total email length
   - `word_count`: Number of words
   - `avg_word_length`: Average word length
   - `uppercase_ratio`: Ratio of uppercase letters
   - `digit_ratio`: Ratio of digits

### Model Architecture

```
Email Text
    ↓
Feature Extraction (14 features)
    ↓
Feature Scaling (StandardScaler)
    ↓
Random Forest Classifier (100 estimators)
    ↓
Prediction: Safe (0) or Phishing (1)
```

## 📊 Model Details

- **Algorithm**: Random Forest Classifier
- **Number of Trees**: 100
- **Max Depth**: 15
- **Training/Test Split**: 70/30
- **Scaling**: StandardScaler normalization

## 🚀 Usage

### Installation

```bash
pip install -r requirements.txt
```

### Running the Model

```bash
python phishing_detector.py
```

### Expected Output

```
============================================================
PHISHING EMAIL DETECTION MODEL
============================================================

1. Creating sample dataset...
   ✓ Generated 24 emails
     - Legitimate: 12
     - Phishing: 12

2. Initializing detector and extracting features...
   ✓ Extracted 14 features per email

3. Splitting data into train/test sets...
   ✓ Training set: 16 emails
   ✓ Test set: 8 emails

4. Training Random Forest model...
   ✓ Model trained successfully!

5. Evaluating model performance...

   Model Performance:
   ✓ Accuracy: 1.0000 (100.00%)
   ✓ ROC-AUC Score: 1.0000

   Confusion Matrix:
   ┌─────────────────┐
   │ TN:   4 | FP:   0 │
   │ FN:   0 | TP:   4 │
   └─────────────────┘

6. Feature Importance Analysis...

7. Example Predictions on Test Set...

8. Generating visualizations...
   ✓ Confusion matrix saved as 'confusion_matrix.png'
   ✓ Feature importance plot saved as 'feature_importance.png'
```

## 📈 Performance Metrics

### Confusion Matrix
- **TN (True Negatives)**: Correctly identified safe emails
- **FP (False Positives)**: Safe emails flagged as phishing
- **FN (False Negatives)**: Phishing emails not detected
- **TP (True Positives)**: Correctly identified phishing emails

### Key Metrics
- **Accuracy**: Overall correctness of predictions
- **Precision**: Accuracy of phishing predictions
- **Recall**: Coverage of actual phishing emails
- **ROC-AUC**: Model discrimination ability

## 🔍 Feature Analysis

The model identifies which features are most important for classification:

1. **Top Features** (typically):
   - Suspicious keyword count
   - Urgent keywords presence
   - URL count and type
   - Verification keywords
   - Uppercase ratio (excessive capitalization)

## 📁 Output Files

- `confusion_matrix.png`: Visualization of confusion matrix
- `feature_importance.png`: Top 10 important features chart

## 🎯 Sample Data

The model includes 24 sample emails:
- **12 Legitimate emails**: Normal business communications
- **12 Phishing emails**: Common phishing tactics with URLs and urgent language

## 🔐 Real-World Applications

To use with real email data:

```python
# Load your email dataset
emails = load_your_emails()  # Your data loading function
labels = load_your_labels()  # 0 = Safe, 1 = Phishing

# Extract features
detector = PhishingEmailDetector()
X = detector.prepare_features(emails)

# Train model
X_train, X_test, y_train, y_test = train_test_split(X, labels)
detector.train(X_train, y_train)

# Make predictions
predictions = detector.predict(X_test)
```

## 📊 Visualization Examples

### Confusion Matrix
Shows the distribution of correct and incorrect predictions across both classes.

### Feature Importance
Displays which email characteristics are most influential in detecting phishing.

## 🛠️ Customization

### Add New Features
Extend the `extract_*_features()` methods in `PhishingEmailDetector` class

### Adjust Model Parameters
Modify hyperparameters in the `train()` method:
- `n_estimators`: Number of trees
- `max_depth`: Tree depth limit
- `min_samples_split`: Minimum samples to split

### Change Dataset
Replace `create_sample_dataset()` with your own email data

## ⚠️ Limitations

- Sample dataset is small (24 emails) - larger datasets improve performance
- Feature extraction based on keywords may miss evolved phishing techniques
- Model requires periodic retraining with new phishing patterns
- Works best with English-language emails

## 🔄 Improvements for Production

1. **Larger Dataset**: Train with thousands of emails
2. **Domain-Specific Features**: Add company-specific URLs and contacts
3. **Sender Analysis**: Verify sender authenticity
4. **Attachment Analysis**: Check file types and extensions
5. **HTML Analysis**: Parse HTML structure and hidden content
6. **NLP Enhancement**: Use deep learning models (LSTM, BERT)
7. **Regular Updates**: Retrain with new phishing patterns monthly

## 📚 References

- [Scikit-learn Documentation](https://scikit-learn.org/)
- [Random Forest Classifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [Email Security Best Practices](https://www.cisa.gov/)

## 📝 License

This project is provided for educational purposes.

## 👨‍💻 Author

Created as part of cybersecurity internship project to demonstrate machine learning applications in email security.
