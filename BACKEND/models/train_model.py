#!/usr/bin/env python
"""
Spam Detection Model Training Script
Trains a machine learning model to detect spam emails
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
import nltk
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, classification_report, confusion_matrix,
                           roc_auc_score, roc_curve)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from utils.preprocess import preprocessor, TextPreprocessor

# Download required NLTK data
print("📥 Downloading NLTK data...")
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)
nltk.download('averaged_perceptron_tagger', quiet=True)
print("✅ NLTK data downloaded")

class SpamModelTrainer:
    """Handle spam detection model training"""
    
    def __init__(self):
        self.models = {}
        self.best_model = None
        self.vectorizer = None
        self.label_encoder = LabelEncoder()
        self.results = {}
        
    def load_data(self, data_path=None):
        """Load and prepare training data"""
        print("\n📊 1. LOADING DATA")
        print("-" * 50)
        
        if data_path and os.path.exists(data_path):
            # Load from file
            df = pd.read_csv(data_path)
            print(f"✅ Loaded dataset from: {data_path}")
        else:
            # Create sample dataset
            print("ℹ️ No dataset found. Creating sample dataset...")
            df = self.create_sample_dataset()
        
        # Display dataset info
        print(f"\n📊 Dataset Statistics:")
        print(f"   • Total emails: {len(df)}")
        print(f"   • Features: {len(df.columns)}")
        print(f"   • Spam: {df['label'].sum()} ({df['label'].sum()/len(df)*100:.1f}%)")
        print(f"   • Ham: {len(df) - df['label'].sum()} ({(len(df) - df['label'].sum())/len(df)*100:.1f}%)")
        
        # Check for class imbalance
        spam_ratio = df['label'].sum() / len(df)
        if spam_ratio < 0.3 or spam_ratio > 0.7:
            print("⚠️ Warning: Dataset shows class imbalance")
        
        return df
    
    def create_sample_dataset(self):
        """Create a comprehensive sample dataset"""
        
        # Spam emails (with variations)
        spam_emails = [
            # Lottery/prize scams
            "URGENT: You have won $1,000,000 in the international lottery! Claim now",
            "CONGRATULATIONS! You've been selected as the winner of our annual prize draw",
            "You are the lucky winner of our Christmas giveaway! Claim your prize",
            "WINNER: Your email has won a brand new iPhone 15. Click here to claim",
            "You've won a free cruise to the Bahamas! Limited time offer",
            
            # Financial scams
            "Your bank account has been compromised. Verify your information immediately",
            "PayPal: Your account has been limited. Please update your details",
            "IMPORTANT: Your credit card has been charged $999. Dispute if unauthorized",
            "IRS Notice: You have an outstanding tax refund of $2,500",
            "Your Netflix subscription is expiring. Update payment method",
            
            # Phishing attempts
            "Verify your Amazon account to prevent suspension",
            "Facebook: Unusual login detected. Confirm your identity",
            "Apple ID: Your account has been locked for security reasons",
            "Microsoft: Password expired. Click to reset",
            "Google: Security alert - new device login",
            
            # Work from home scams
            "Work from home and earn $5000/week! No experience needed",
            "Make money online with this simple trick. Start earning today",
            "Become a mystery shopper - earn $200 per assignment",
            "Bitcoin investment opportunity - 1000% returns guaranteed",
            "Forex trading secrets revealed - make millions",
            
            # Product promotions
            "50% OFF on all medications - Viagra, Cialis, and more",
            "Get your degree in 6 months! Accredited online university",
            "Lose weight fast with our miracle diet pill",
            "Increase your followers by 10,000 in 24 hours",
            "Rolex replicas - 90% off retail price",
            
            # Dating/romance
            "Hot singles in your area want to meet you",
            "Someone likes you! Click to see who",
            "Find your soulmate today - special matchmaking offer",
            "Russian brides waiting for you",
            "Local women are looking for men",
            
            # Malware alerts
            "YOUR COMPUTER HAS A VIRUS! Scan now",
            "Warning: 5 viruses detected. Download cleaner",
            "Your system is infected. Click to remove malware",
            "Critical security alert: Update your antivirus",
            "Your files will be deleted unless you pay",
            
            # Miscellaneous spam
            "You have 1 unread message from admin",
            "Your package delivery failed - click here",
            "New voicemail from unknown number",
            "You've been mentioned in a comment",
            "Your account will be deleted in 24 hours"
        ]
        
        # Ham (legitimate) emails
        ham_emails = [
            # Work-related
            "Meeting scheduled for tomorrow at 3 PM in Conference Room A",
            "Please find attached the quarterly report for Q3 2024",
            "Can you review my pull request when you have a moment?",
            "Project deadline extended to next Friday due to holidays",
            "Team lunch this Friday at 12:30 PM - please RSVP",
            
            # Personal
            "Hey, are we still on for dinner tonight at 7?",
            "Mom - can you pick up milk and bread on your way home?",
            "Great seeing you yesterday! Let's do it again soon",
            "Happy Birthday! Hope you have a wonderful day",
            "Thanks for the gift - I love it!",
            
            # Business
            "Your invoice #INV-2024-001 has been paid",
            "Welcome to our platform! Here's how to get started",
            "Your support ticket #12345 has been resolved",
            "Thank you for your purchase. Order confirmation attached",
            "Your subscription has been successfully renewed",
            
            # Notifications
            "Your password was changed successfully",
            "New login from Chrome on Windows detected",
            "Two-factor authentication enabled for your account",
            "Your profile has been updated",
            "Weekly digest: 3 new notifications",
            
            # Professional
            "Invitation: Tech Conference 2024 - Keynote Speaker",
            "Job Application: Thank you for your interest",
            "Interview scheduled for Software Engineer position",
            "Your resume has been received and is under review",
            "Networking event next week - would you like to attend?",
            
            # Educational
            "Course registration now open for Spring semester",
            "Your certificate of completion is ready to download",
            "New course materials have been uploaded",
            "Reminder: Assignment due this Friday",
            "Guest lecture next Tuesday - attendance required",
            
            # Transactional
            "Your Uber receipt for trip on Oct 15",
            "Amazon order #123-4567890 has shipped",
            "Your table reservation at Italian Bistro is confirmed",
            "Flight confirmation: AA1234 - New York to Chicago",
            "Hotel booking confirmed for Dec 20-25",
            
            # Newsletters
            "TechCrunch Weekly: Top stories this week",
            "The Morning Brew - Your daily business news",
            "Product Hunt Daily: Best new products",
            "Medium Daily Digest: Articles you might like",
            "LinkedIn: New jobs matching your profile"
        ]
        
        # Create labels (1 for spam, 0 for ham)
        spam_labels = [1] * len(spam_emails)
        ham_labels = [0] * len(ham_emails)
        
        # Combine
        emails = spam_emails + ham_emails
        labels = spam_labels + ham_labels
        
        # Create subjects from first few words
        subjects = [' '.join(email.split()[:5]) for email in emails]
        
        # Create DataFrame
        df = pd.DataFrame({
            'email': emails,
            'subject': subjects,
            'label': labels
        })
        
        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save dataset
        os.makedirs('data', exist_ok=True)
        df.to_csv('data/spam_dataset.csv', index=False)
        
        print(f"✅ Created sample dataset with {len(df)} emails")
        return df
    
    def preprocess_data(self, df):
        """Preprocess email text"""
        print("\n🔧 2. PREPROCESSING DATA")
        print("-" * 50)
        
        # Combine subject and email
        df['full_text'] = df['subject'] + " " + df['email']
        
        # Apply preprocessing
        print("   Applying text preprocessing...")
        df['processed_text'] = df['full_text'].apply(preprocessor.preprocess)
        
        # Show samples
        print("\n   📝 Preprocessing Examples:")
        for i in range(min(3, len(df))):
            print(f"\n   Original: {df['full_text'].iloc[i][:100]}...")
            print(f"   Processed: {df['processed_text'].iloc[i][:100]}...")
        
        return df
    
    def create_features(self, df):
        """Create TF-IDF features"""
        print("\n📈 3. FEATURE ENGINEERING")
        print("-" * 50)
        
        # Initialize TF-IDF vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.8,
            strip_accents='unicode',
            lowercase=True,
            analyzer='word',
            token_pattern=r'\w{1,}',
            sublinear_tf=True
        )
        
        # Transform text to features
        print("   Creating TF-IDF features...")
        X = self.vectorizer.fit_transform(df['processed_text'])
        
        print(f"   Feature matrix shape: {X.shape}")
        print(f"   Vocabulary size: {len(self.vectorizer.vocabulary_)}")
        print(f"   Sparsity: {(X.nnz / (X.shape[0] * X.shape[1]) * 100):.2f}%")
        
        return X, df['label'].values
    
    def train_models(self, X, y):
        """Train multiple models and compare"""
        print("\n🤖 4. TRAINING MODELS")
        print("-" * 50)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"   Training set: {X_train.shape[0]} samples")
        print(f"   Test set: {X_test.shape[0]} samples")
        
        # Define models to try
        models_to_try = {
            'Naive Bayes': MultinomialNB(alpha=0.1),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'SVM': SVC(kernel='linear', probability=True, random_state=42)
        }
        
        # Train and evaluate each model
        print("\n   📊 Model Performance:")
        print("   " + "-" * 65)
        print(f"   {'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10}")
        print("   " + "-" * 65)
        
        best_f1 = 0
        
        for name, model in models_to_try.items():
            # Train model
            model.fit(X_train, y_train)
            
            # Make predictions
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            # Store results
            self.models[name] = model
            self.results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
            
            # Print results
            print(f"   {name:<20} {accuracy:<10.3f} {precision:<10.3f} {recall:<10.3f} {f1:<10.3f}")
            
            # Track best model
            if f1 > best_f1:
                best_f1 = f1
                self.best_model = model
                self.best_model_name = name
        
        print("   " + "-" * 65)
        print(f"\n   ✅ Best model: {self.best_model_name} (F1: {best_f1:.3f})")
        
        return X_test, y_test
    
    def evaluate_model(self, X_test, y_test):
        """Detailed evaluation of best model"""
        print("\n📊 5. DETAILED EVALUATION")
        print("-" * 50)
        
        # Make predictions
        y_pred = self.best_model.predict(X_test)
        y_prob = self.best_model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        auc_roc = roc_auc_score(y_test, y_prob)
        
        print(f"\n   🎯 Overall Metrics:")
        print(f"      • Accuracy:  {accuracy:.3f} ({accuracy*100:.1f}%)")
        print(f"      • Precision: {precision:.3f} ({precision*100:.1f}%)")
        print(f"      • Recall:    {recall:.3f} ({recall*100:.1f}%)")
        print(f"      • F1-Score:  {f1:.3f} ({f1*100:.1f}%)")
        print(f"      • AUC-ROC:   {auc_roc:.3f}")
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print(f"\n   📊 Confusion Matrix:")
        print(f"      TN: {cm[0][0]:4d}  FP: {cm[0][1]:4d}")
        print(f"      FN: {cm[1][0]:4d}  TP: {cm[1][1]:4d}")
        
        # Classification Report
        print(f"\n   📋 Classification Report:")
        report = classification_report(y_test, y_pred, target_names=['Ham', 'Spam'])
        for line in report.split('\n')[2:5]:
            print(f"      {line}")
        
        # Cross-validation
        cv_scores = cross_val_score(self.best_model, X_test, y_test, cv=5)
        print(f"\n   🔄 Cross-validation (5-fold):")
        print(f"      Mean: {cv_scores.mean():.3f} (±{cv_scores.std()*2:.3f})")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'auc_roc': auc_roc,
            'confusion_matrix': cm.tolist()
        }
    
    def feature_importance(self, feature_names, top_n=20):
        """Analyze feature importance"""
        print("\n🔍 6. FEATURE IMPORTANCE")
        print("-" * 50)
        
        if hasattr(self.best_model, 'coef_'):
            # For linear models
            importance = np.abs(self.best_model.coef_[0])
            feature_importance = list(zip(feature_names, importance))
            feature_importance.sort(key=lambda x: x[1], reverse=True)
            
            print(f"\n   Top {top_n} Most Important Features:")
            print("   " + "-" * 40)
            for i, (feature, imp) in enumerate(feature_importance[:top_n], 1):
                print(f"   {i:2d}. {feature:<30} {imp:.4f}")
            
            return feature_importance
        else:
            print("   ℹ️ Feature importance not available for this model")
            return []
    
    def test_predictions(self, test_emails=None):
        """Test model with sample emails"""
        print("\n🧪 7. TEST PREDICTIONS")
        print("-" * 50)
        
        if test_emails is None:
            test_emails = [
                "Win a free iPhone! Click here to claim your prize now",
                "Meeting at 3pm tomorrow to discuss the project deadline",
                "URGENT: Your PayPal account has been limited. Verify now",
                "Thank you for your purchase. Your order has been shipped",
                "You've won the lottery! Send money to claim your prize",
                "Can you review the attached document when you have time?",
                "Your Netflix subscription is expiring. Update payment method",
                "Team lunch this Friday at 12:30 PM - please let me know if you can make it"
            ]
        
        print("\n   Sample Predictions:")
        print("   " + "-" * 70)
        print(f"   {'Email':<50} {'Prediction':<12} {'Confidence':<10}")
        print("   " + "-" * 70)
        
        for email in test_emails:
            # Preprocess
            processed = preprocessor.preprocess(email)
            
            # Vectorize
            vectorized = self.vectorizer.transform([processed])
            
            # Predict
            pred = self.best_model.predict(vectorized)[0]
            proba = self.best_model.predict_proba(vectorized)[0]
            
            result = "🔴 SPAM" if pred == 1 else "🟢 HAM"
            confidence = max(proba) * 100
            
            # Truncate email for display
            email_display = email[:47] + "..." if len(email) > 50 else email
            print(f"   {email_display:<50} {result:<12} {confidence:>6.1f}%")
    
    def save_model(self):
        """Save model and vectorizer"""
        print("\n💾 8. SAVING MODEL")
        print("-" * 50)
        
        # Create models directory
        os.makedirs('models', exist_ok=True)
        
        # Save paths
        model_path = 'models/spam_model.pkl'
        vectorizer_path = 'models/tfidf_vectorizer.pkl'
        
        # Save best model
        joblib.dump(self.best_model, model_path)
        print(f"   ✅ Model saved to: {model_path}")
        print(f"      • Type: {type(self.best_model).__name__}")
        print(f"      • Size: {os.path.getsize(model_path) / 1024:.1f} KB")
        
        # Save vectorizer
        joblib.dump(self.vectorizer, vectorizer_path)
        print(f"   ✅ Vectorizer saved to: {vectorizer_path}")
        print(f"      • Vocabulary size: {len(self.vectorizer.vocabulary_)}")
        print(f"      • Size: {os.path.getsize(vectorizer_path) / 1024:.1f} KB")
        
        # Save model info
        info = {
            'model_type': type(self.best_model).__name__,
            'features': len(self.vectorizer.vocabulary_),
            'metrics': self.results[self.best_model_name],
            'training_date': pd.Timestamp.now().isoformat(),
            'version': '1.0'
        }
        
        info_path = 'models/model_info.json'
        pd.Series(info).to_json(info_path)
        print(f"   ✅ Model info saved to: {info_path}")
        
        return model_path, vectorizer_path
    
    def run_pipeline(self, data_path=None):
        """Run complete training pipeline"""
        print("\n" + "=" * 70)
        print("🚀 SPAM DETECTION MODEL TRAINING PIPELINE")
        print("=" * 70)
        
        # 1. Load data
        df = self.load_data(data_path)
        
        # 2. Preprocess
        df = self.preprocess_data(df)
        
        # 3. Create features
        X, y = self.create_features(df)
        
        # 4. Train models
        X_test, y_test = self.train_models(X, y)
        
        # 5. Evaluate best model
        metrics = self.evaluate_model(X_test, y_test)
        
        # 6. Feature importance
        feature_names = self.vectorizer.get_feature_names_out()
        self.feature_importance(feature_names)
        
        # 7. Test predictions
        self.test_predictions()
        
        # 8. Save model
        model_path, vectorizer_path = self.save_model()
        
        # Summary
        print("\n" + "=" * 70)
        print("✅ TRAINING COMPLETE!")
        print("=" * 70)
        print(f"\n📊 Final Model: {self.best_model_name}")
        print(f"   • Accuracy:  {metrics['accuracy']*100:.2f}%")
        print(f"   • Precision: {metrics['precision']*100:.2f}%")
        print(f"   • Recall:    {metrics['recall']*100:.2f}%")
        print(f"   • F1-Score:  {metrics['f1']*100:.2f}%")
        print(f"\n📁 Model files:")
        print(f"   • {model_path}")
        print(f"   • {vectorizer_path}")
        print("\n" + "=" * 70)
        
        return self.best_model, self.vectorizer

def create_simple_model():
    """Create a simple model quickly for testing"""
    print("\n" + "=" * 70)
    print("⚡ CREATING SIMPLE SPAM MODEL")
    print("=" * 70)
    
    # Sample data
    spam_emails = [
        "win lottery prize money claim now",
        "free iphone click here",
        "urgent account verify password",
        "you have won million dollars",
        "hot singles in your area",
        "make money from home fast",
        "your account has been compromised",
        "claim your prize today",
        "limited time offer discount",
        "buy cheap medications online"
    ]
    
    ham_emails = [
        "meeting at 3pm tomorrow",
        "please review the attached document",
        "thank you for your purchase",
        "can we meet on friday",
        "project deadline extended",
        "happy birthday hope you have a great day",
        "see you at the conference",
        "thanks for your help",
        "let's have lunch sometime",
        "your order has been shipped"
    ]
    
    # Create dataset
    emails = spam_emails + ham_emails
    labels = [1] * len(spam_emails) + [0] * len(ham_emails)
    
    df = pd.DataFrame({'email': emails, 'label': labels})
    
    # Preprocess
    print("\n1. Preprocessing emails...")
    df['processed'] = df['email'].apply(preprocessor.preprocess)
    
    # Vectorize
    print("2. Creating TF-IDF features...")
    vectorizer = TfidfVectorizer(max_features=100)
    X = vectorizer.fit_transform(df['processed'])
    
    # Train
    print("3. Training model...")
    model = MultinomialNB()
    model.fit(X, df['label'])
    
    # Save
    print("4. Saving model...")
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/spam_model.pkl')
    joblib.dump(vectorizer, 'models/tfidf_vectorizer.pkl')
    
    print("\n✅ Simple model created successfully!")
    print(f"   Model saved to: models/spam_model.pkl")
    print(f"   Vectorizer saved to: models/tfidf_vectorizer.pkl")
    
    return model, vectorizer

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train spam detection model')
    parser.add_argument('--data', type=str, help='Path to training data CSV')
    parser.add_argument('--simple', action='store_true', help='Create simple model for testing')
    parser.add_argument('--quick', action='store_true', help='Quick training (uses default model)')
    
    args = parser.parse_args()
    
    if args.simple:
        # Create simple model
        create_simple_model()
    elif args.quick:
        # Quick training with default model
        trainer = SpamModelTrainer()
        trainer.run_pipeline(data_path=args.data)
    else:
        # Full training with model comparison
        trainer = SpamModelTrainer()
        trainer.run_pipeline(data_path=args.data)