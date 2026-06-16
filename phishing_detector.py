"""
Phishing Email Detection Model
Uses machine learning to classify emails as Phishing or Safe
"""

import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Tuple, List, Dict
import warnings
warnings.filterwarnings('ignore')


class PhishingEmailDetector:
    """
    Machine learning model for detecting phishing emails
    """
    
    def __init__(self):
        self.model = None
        self.tfidf = TfidfVectorizer(max_features=100, stop_words='english')
        self.scaler = StandardScaler()
        self.feature_names = []
        
    def extract_url_features(self, email_text: str) -> Dict[str, int]:
        """
        Extract URL-based features from email text
        
        Features:
        - Number of URLs
        - Number of suspicious URLs (shortened, IP-based)
        - URL domain variations
        """
        features = {
            'url_count': 0,
            'suspicious_url_count': 0,
            'ip_based_url': 0,
            'short_url': 0,
        }
        
        # Find all URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_text)
        features['url_count'] = len(urls)
        
        # Check for suspicious URL patterns
        suspicious_patterns = ['bit.ly', 'tinyurl', 'short.link', 'goo.gl']
        for url in urls:
            if any(pattern in url for pattern in suspicious_patterns):
                features['suspicious_url_count'] += 1
                features['short_url'] += 1
            
            # Check for IP-based URLs
            if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
                features['ip_based_url'] += 1
                features['suspicious_url_count'] += 1
        
        return features
    
    def extract_keyword_features(self, email_text: str) -> Dict[str, int]:
        """
        Extract phishing-related keyword features
        """
        email_lower = email_text.lower()
        features = {
            'urgent_keywords': 0,
            'suspicious_keywords': 0,
            'financial_keywords': 0,
            'verification_keywords': 0,
            'exclamation_count': 0,
        }
        
        # Urgent action keywords
        urgent_keywords = ['urgent', 'action required', 'immediately', 'asap', 'verify now']
        for keyword in urgent_keywords:
            features['urgent_keywords'] += email_lower.count(keyword)
        
        # Suspicious keywords
        suspicious_keywords = ['confirm identity', 'update payment', 'suspicious activity', 
                              'unusual access', 'click here', 'verify account']
        for keyword in suspicious_keywords:
            features['suspicious_keywords'] += email_lower.count(keyword)
        
        # Financial keywords
        financial_keywords = ['bank', 'credit card', 'payment', 'billing', 'transaction', 'account']
        for keyword in financial_keywords:
            features['financial_keywords'] += email_lower.count(keyword)
        
        # Verification keywords
        verification_keywords = ['verify', 'confirm', 'authenticate', 'validate', 'reactivate']
        for keyword in verification_keywords:
            features['verification_keywords'] += email_lower.count(keyword)
        
        # Count exclamation marks (often used in phishing)
        features['exclamation_count'] = email_text.count('!')
        
        return features
    
    def extract_structural_features(self, email_text: str) -> Dict[str, float]:
        """
        Extract structural features from email
        """
        features = {
            'text_length': len(email_text),
            'word_count': len(email_text.split()),
            'avg_word_length': np.mean([len(word) for word in email_text.split()]) if email_text.split() else 0,
            'uppercase_ratio': sum(1 for c in email_text if c.isupper()) / max(len(email_text), 1),
            'digit_ratio': sum(1 for c in email_text if c.isdigit()) / max(len(email_text), 1),
        }
        return features
    
    def extract_email_features(self, email_text: str) -> np.ndarray:
        """
        Extract all features from an email
        """
        url_features = self.extract_url_features(email_text)
        keyword_features = self.extract_keyword_features(email_text)
        structural_features = self.extract_structural_features(email_text)
        
        # Combine all features
        all_features = {**url_features, **keyword_features, **structural_features}
        
        return np.array(list(all_features.values())).reshape(1, -1)
    
    def prepare_features(self, emails: List[str]) -> np.ndarray:
        """
        Extract features for a list of emails
        """
        all_features = []
        
        for email in emails:
            url_features = self.extract_url_features(email)
            keyword_features = self.extract_keyword_features(email)
            structural_features = self.extract_structural_features(email)
            
            combined = {**url_features, **keyword_features, **structural_features}
            all_features.append(list(combined.values()))
        
        return np.array(all_features)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train the phishing detection model
        """
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Initialize and train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        print("✓ Model trained successfully!")
    
    def predict(self, X_test: np.ndarray) -> np.ndarray:
        """
        Make predictions on test data
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        X_test_scaled = self.scaler.transform(X_test)
        return self.model.predict(X_test_scaled)
    
    def predict_proba(self, X_test: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        X_test_scaled = self.scaler.transform(X_test)
        return self.model.predict_proba(X_test_scaled)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Evaluate model performance
        """
        y_pred = self.predict(X_test)
        y_pred_proba = self.predict_proba(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
        
        results = {
            'accuracy': accuracy,
            'confusion_matrix': conf_matrix,
            'roc_auc': roc_auc,
            'predictions': y_pred,
            'probabilities': y_pred_proba
        }
        
        return results
    
    def get_feature_importance(self) -> pd.DataFrame:
        """
        Get feature importance from the model
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        feature_names = [
            'url_count', 'suspicious_url_count', 'ip_based_url', 'short_url',
            'urgent_keywords', 'suspicious_keywords', 'financial_keywords',
            'verification_keywords', 'exclamation_count', 'text_length',
            'word_count', 'avg_word_length', 'uppercase_ratio', 'digit_ratio'
        ]
        
        importances = self.model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        return feature_importance_df


def plot_confusion_matrix(cm: np.ndarray, title: str = "Confusion Matrix"):
    """
    Plot confusion matrix heatmap
    """
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Safe', 'Phishing'],
                yticklabels=['Safe', 'Phishing'],
                cbar_kws={'label': 'Count'})
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.title(title)
    plt.tight_layout()
    return plt


def plot_feature_importance(feature_importance_df: pd.DataFrame, top_n: int = 10):
    """
    Plot top N important features
    """
    plt.figure(figsize=(10, 6))
    top_features = feature_importance_df.head(top_n)
    plt.barh(range(len(top_features)), top_features['importance'].values)
    plt.yticks(range(len(top_features)), top_features['feature'].values)
    plt.xlabel('Importance')
    plt.title(f'Top {top_n} Important Features')
    plt.tight_layout()
    return plt


def create_sample_dataset() -> Tuple[List[str], np.ndarray]:
    """
    Create a sample dataset of phishing and legitimate emails
    """
    
    # Legitimate emails
    legitimate_emails = [
        "Hi John, Your monthly report is ready for review. Please download it from our secure portal.",
        "Welcome to our newsletter! This month we have great updates on our new product line.",
        "Your order #12345 has been shipped. Track your package here: https://www.legitimate-shipping.com/track",
        "Team meeting reminder: Next week at 2 PM in Conference Room B. Please prepare your slides.",
        "Thank you for your purchase! Your receipt is attached to this email.",
        "Project update: We're on schedule for the Q4 launch. Great work everyone!",
        "Colleague notification: John Smith has been promoted to Senior Developer. Congrats!",
        "Documentation link: Check out our latest API documentation at https://docs.ourcompany.com",
        "Event invitation: Join us for our annual company picnic this Saturday at Central Park!",
        "Password reset successful: Your password has been changed as requested on our platform.",
        "Invoice #INV-2024-001 for March services is now available for download.",
        "Your support ticket #5678 has been resolved. Thank you for contacting us!",
    ]
    
    # Phishing emails
    phishing_emails = [
        "URGENT!!! Your account has been compromised! Click here immediately to verify your identity: http://193.168.1.100/verify",
        "Action required: Confirm your banking credentials now! http://bit.ly/bankverify Click immediately!",
        "Your Apple ID has been locked due to suspicious activity. Verify account: http://tinyurl.com/appleverify",
        "ALERT: Unusual access detected! Reactivate your account NOW: http://192.168.1.1/reactivate URGENT!!!",
        "Verify your payment information immediately! http://short.link/paymentverify Your account will be terminated!",
        "Re-activate your account: Unusual access detected on your account. Update payment info: http://goo.gl/confirm",
        "URGENT ACTION REQUIRED: Confirm your identity within 24 hours! http://fake-bank.com/verify Click here!",
        "Your credit card transaction failed! Update billing information: http://bit.ly/billingupdate ASAP!",
        "Bank security alert: Suspicious transaction detected. Authenticate now: http://phishing-site.net/auth",
        "URGENT: Your account will be suspended! Verify your email: http://shortlink.io/verify",
        "Urgent: Confirm your identity to continue using our service. Click: http://193.168.0.1/confirm NOW!!!",
        "Action required: Update your password immediately! http://bit.ly/resetpass Your account is at risk!",
    ]
    
    # Combine and create labels
    all_emails = legitimate_emails + phishing_emails
    labels = np.array([0] * len(legitimate_emails) + [1] * len(phishing_emails))
    
    return all_emails, labels


def main():
    """
    Main execution function
    """
    print("=" * 60)
    print("PHISHING EMAIL DETECTION MODEL")
    print("=" * 60)
    
    # Create sample dataset
    print("\n1. Creating sample dataset...")
    emails, labels = create_sample_dataset()
    print(f"   ✓ Generated {len(emails)} emails")
    print(f"     - Legitimate: {np.sum(labels == 0)}")
    print(f"     - Phishing: {np.sum(labels == 1)}")
    
    # Initialize detector
    print("\n2. Initializing detector and extracting features...")
    detector = PhishingEmailDetector()
    X = detector.prepare_features(emails)
    print(f"   ✓ Extracted {X.shape[1]} features per email")
    
    # Split data
    print("\n3. Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.3, random_state=42, stratify=labels
    )
    print(f"   ✓ Training set: {X_train.shape[0]} emails")
    print(f"   ✓ Test set: {X_test.shape[0]} emails")
    
    # Train model
    print("\n4. Training Random Forest model...")
    detector.train(X_train, y_train)
    
    # Evaluate model
    print("\n5. Evaluating model performance...")
    results = detector.evaluate(X_test, y_test)
    
    accuracy = results['accuracy']
    conf_matrix = results['confusion_matrix']
    roc_auc = results['roc_auc']
    
    print(f"\n   Model Performance:")
    print(f"   ✓ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   ✓ ROC-AUC Score: {roc_auc:.4f}")
    print(f"\n   Confusion Matrix:")
    print(f"   ┌─────────────────┐")
    print(f"   │ TN: {conf_matrix[0,0]:3d} | FP: {conf_matrix[0,1]:3d} │")
    print(f"   │ FN: {conf_matrix[1,0]:3d} | TP: {conf_matrix[1,1]:3d} │")
    print(f"   └─────────────────┘")
    
    # Detailed classification report
    y_pred = results['predictions']
    print(f"\n   Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    # Feature importance
    print("\n6. Feature Importance Analysis...")
    feature_importance = detector.get_feature_importance()
    print("\n   Top 10 Most Important Features:")
    for idx, row in feature_importance.head(10).iterrows():
        print(f"   {idx+1}. {row['feature']:25s}: {row['importance']:.4f}")
    
    # Example predictions
    print("\n7. Example Predictions on Test Set:")
    print(f"   {'Email Type':<15} {'Predicted':<15} {'Confidence':<15}")
    print("   " + "-" * 45)
    
    for i in range(min(5, len(y_test))):
        true_label = "Phishing" if y_test[i] == 1 else "Safe"
        pred_label = "Phishing" if y_pred[i] == 1 else "Safe"
        confidence = results['probabilities'][i][y_pred[i]]
        print(f"   {true_label:<15} {pred_label:<15} {confidence:<15.2%}")
    
    # Create visualizations
    print("\n8. Generating visualizations...")
    
    # Confusion Matrix Plot
    plot_confusion_matrix(conf_matrix)
    plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
    print("   ✓ Confusion matrix saved as 'confusion_matrix.png'")
    
    # Feature Importance Plot
    plot_feature_importance(feature_importance)
    plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
    print("   ✓ Feature importance plot saved as 'feature_importance.png'")
    
    print("\n" + "=" * 60)
    print("PHISHING DETECTION MODEL TRAINING COMPLETE!")
    print("=" * 60)
    
    return detector, results


if __name__ == "__main__":
    detector, results = main()
