"""
Email analysis routes for spam and phishing detection
"""

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from flask_login.config import timedelta
from utils.database import db
from models.user import AnalysisHistory
from utils.preprocess import preprocessor
import joblib
import logging
import os
import time
import json
from datetime import datetime, timedelta
from collections import Counter

logger = logging.getLogger(__name__)
analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/analysis')

# Load model and vectorizer
model = None
vectorizer = None
model_metadata = {
    'loaded': False,
    'model_type': None,
    'features': 0,
    'last_loaded': None,
    'version': '1.0'
}

def load_model():
    """Load the spam detection model"""
    global model, vectorizer, model_metadata
    
    try:
        model_path = current_app.config.get('MODEL_PATH', 'models/spam_model.pkl')
        vectorizer_path = current_app.config.get('VECTORIZER_PATH', 'models/tfidf_vectorizer.pkl')
        
        # Check if files exist
        if not os.path.exists(model_path):
            logger.warning(f"⚠️ Model file not found at: {model_path}")
            return False
            
        if not os.path.exists(vectorizer_path):
            logger.warning(f"⚠️ Vectorizer file not found at: {vectorizer_path}")
            return False
        
        # Load model and vectorizer
        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
        
        # Update metadata
        model_metadata.update({
            'loaded': True,
            'model_type': type(model).__name__,
            'features': len(vectorizer.vocabulary_) if hasattr(vectorizer, 'vocabulary_') else 0,
            'last_loaded': datetime.utcnow().isoformat(),
            'version': '1.0'
        })
        
        logger.info(f"✅ Model loaded successfully: {model_metadata['model_type']}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error loading model: {str(e)}")
        model_metadata['loaded'] = False
        model_metadata['error'] = str(e)
        return False

def analyze_with_ml(email_text):
    """Analyze email using ML model"""
    try:
        # Preprocess text
        processed_text = preprocessor.preprocess(email_text)
        
        # Vectorize
        text_vectorized = vectorizer.transform([processed_text])
        
        # Get prediction
        prediction = model.predict(text_vectorized)[0]
        probabilities = model.predict_proba(text_vectorized)[0]
        
        # Get probabilities (assuming binary classification)
        prob_spam = float(probabilities[1]) if len(probabilities) > 1 else 0
        prob_ham = float(probabilities[0]) if len(probabilities) > 0 else 0
        
        # Determine if spam
        is_spam = bool(prediction)
        confidence = float(max(probabilities))
        
        # Determine category
        if is_spam:
            # Check for phishing indicators
            text_lower = email_text.lower()
            phishing_indicators = ['verify', 'account', 'password', 'bank', 'login', 
                                  'credit card', 'social security', 'ssn', 'paypal']
            
            if any(indicator in text_lower for indicator in phishing_indicators):
                category = 'Phishing'
            else:
                category = 'Spam'
            
            explanation = "This email has been classified as spam based on its content patterns."
        else:
            category = 'Legitimate'
            explanation = "This email appears to be legitimate and safe."
        
        return {
            'is_spam': is_spam,
            'confidence': confidence,
            'probability_spam': prob_spam,
            'probability_ham': prob_ham,
            'category': category,
            'explanation': explanation,
            'method': 'ml'
        }
        
    except Exception as e:
        logger.error(f"ML analysis error: {str(e)}")
        return None

def analyze_with_rules(email_subject, email_content):
    """Fallback rule-based analysis when ML model is not available"""
    
    text = f"{email_subject} {email_content}".lower()
    
    # Spam keywords with weights
    spam_keywords = {
        'winner': 15, 'win': 10, 'won': 15, 'lottery': 20, 'prize': 15,
        'free': 10, 'cash': 15, 'money': 10, 'urgent': 10, 'verify': 15,
        'account': 10, 'click': 10, 'link': 10, 'password': 20, 'bank': 20,
        'paypal': 20, 'credit card': 25, 'social security': 30, 'ssn': 30,
        'inheritance': 25, 'prince': 30, 'million': 25, 'billion': 25,
        'dollars': 15, 'earn': 10, 'income': 10, 'investment': 15,
        'guaranteed': 20, 'limited time': 15, 'act now': 15,
        'call now': 15, 'offer expires': 15, 'risk-free': 20,
        'no cost': 15, 'no fees': 15, 'cheap': 10, 'discount': 10
    }
    
    # Phishing indicators with weights
    phishing_indicators = {
        'verify your account': 25,
        'account suspended': 25,
        'account limited': 25,
        'unusual activity': 20,
        'sign in': 15,
        'update your': 20,
        'confirm your': 20,
        'security measure': 20,
        'unauthorized': 25,
        'breach': 30,
        'compromised': 30,
        'unusual sign-in': 25,
        'recent login': 15,
        'new device': 15,
        'unrecognized': 20,
        'locked out': 25
    }
    
    # Suspicious patterns
    suspicious_patterns = {
        r'\b\d{16}\b': 30,  # Credit card number
        r'\b\d{3}-\d{2}-\d{4}\b': 30,  # SSN
        r'password\s*:': 25,  # Asking for password
        r'username\s*:': 20,  # Asking for username
        r'login\s*:': 20,     # Asking for login
        r'http[s]?://(?:[^\s]+)': 10,  # URLs
    }
    
    score = 0
    detected_keywords = []
    risk_factors = []
    
    # Check spam keywords
    for keyword, weight in spam_keywords.items():
        if keyword in text:
            score += weight
            detected_keywords.append(keyword)
            risk_factors.append(f"Contains spam keyword: '{keyword}'")
    
    # Check phishing indicators
    for indicator, weight in phishing_indicators.items():
        if indicator in text:
            score += weight
            detected_keywords.append(indicator[:20])
            risk_factors.append(f"Contains phishing indicator: '{indicator}'")
    
    # Check suspicious patterns
    import re
    for pattern, weight in suspicious_patterns.items():
        if re.search(pattern, text):
            score += weight
            risk_factors.append(f"Contains sensitive data pattern")
    
    # Check for excessive punctuation/caps
    if text.count('!') > 3:
        score += 5
        risk_factors.append("Excessive exclamation marks")
    
    if text.count('?') > 3:
        score += 5
        risk_factors.append("Excessive question marks")
    
    # Check for ALL CAPS words
    words = text.split()
    caps_ratio = sum(1 for w in words if w.isupper() and len(w) > 2) / len(words) if words else 0
    if caps_ratio > 0.3:
        score += 10
        risk_factors.append(f"High ratio of ALL CAPS words ({caps_ratio:.0%})")
    
    # Normalize score to 0-100
    score = min(score, 100)
    
    # Determine category and explanation
    if score >= 70:
        if any(indicator in text for indicator in ['verify', 'account', 'password', 'bank', 'ssn']):
            category = 'Phishing'
            explanation = "⚠️ HIGH RISK: This appears to be a phishing attempt. It contains urgent requests for personal information."
        else:
            category = 'Spam'
            explanation = "⚠️ HIGH RISK: This appears to be spam. It contains promotional or scam indicators."
    elif score >= 40:
        category = 'Suspicious'
        explanation = "⚡ MEDIUM RISK: This email contains some suspicious elements. Exercise caution before responding or clicking links."
    else:
        category = 'Legitimate'
        explanation = "✅ LOW RISK: This email appears to be legitimate and safe."
    
    is_spam = score >= 40
    confidence = score / 100.0
    probability_spam = confidence
    probability_ham = 1 - confidence
    
    return {
        'is_spam': is_spam,
        'confidence': confidence,
        'probability_spam': probability_spam,
        'probability_ham': probability_ham,
        'category': category,
        'explanation': explanation,
        'risk_score': score,
        'detected_keywords': list(set(detected_keywords))[:10],
        'risk_factors': risk_factors[:5],
        'method': 'rules'
    }

def generate_recommendations(analysis_result):
    """Generate recommendations based on analysis"""
    recommendations = []
    
    if analysis_result['is_spam']:
        if analysis_result['category'] == 'Phishing':
            recommendations.extend([
                "❌ Do NOT click any links in this email",
                "❌ Do NOT download any attachments",
                "❌ Do NOT reply or provide any personal information",
                "🔒 If concerned, contact the company directly using their official website",
                "📧 Report this email as phishing to your email provider"
            ])
        else:
            recommendations.extend([
                "❌ Mark this email as spam",
                "❌ Delete the email without responding",
                "🔒 Be cautious of similar emails in the future",
                "📧 Consider blocking the sender"
            ])
    else:
        recommendations.extend([
            "✅ This email appears safe to interact with",
            "🔒 Still exercise caution with any links or attachments",
            "📧 Regular email safety practices apply"
        ])
    
    return recommendations

# Load model on module import
load_model()

@analysis_bp.route('/analyze', methods=['POST'])
@login_required
def analyze_email():
    """Analyze a single email for spam/phishing"""
    
    start_time = time.time()
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email_subject = data.get('subject', '').strip()
        email_content = data.get('content', '').strip()
        
        if not email_content:
            return jsonify({'error': 'Email content is required'}), 400
        
        # Combine subject and content for analysis
        full_text = f"{email_subject} {email_content}".strip()
        
        # Perform analysis
        if model and vectorizer:
            # ML-based analysis
            result = analyze_with_ml(full_text)
            if not result:
                # Fallback to rules if ML fails
                result = analyze_with_rules(email_subject, email_content)
                logger.warning(f"ML analysis failed, using rule-based for user {current_user.username}")
        else:
            # Rule-based analysis
            result = analyze_with_rules(email_subject, email_content)
            logger.info(f"Using rule-based analysis for user {current_user.username}")
        
        # Generate recommendations
        result['recommendations'] = generate_recommendations(result)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        result['processing_time'] = round(processing_time, 3)
        
        # Save to history
        try:
            history = AnalysisHistory(
                user_id=current_user.id,
                email_subject=email_subject[:200],
                email_content=email_content[:1000],  # Store only first 1000 chars
                is_spam=result['is_spam'],
                confidence=result['confidence'],
                probability_spam=result.get('probability_spam', result['confidence'] if result['is_spam'] else 1-result['confidence']),
                probability_ham=result.get('probability_ham', 1-result['confidence'] if result['is_spam'] else result['confidence']),
                category=result['category'],
                explanation=result['explanation'],
                processing_time=processing_time,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                detected_keywords=json.dumps(result.get('detected_keywords', [])),
                risk_factors=json.dumps(result.get('risk_factors', [])),
                recommendations=json.dumps(result.get('recommendations', []))
            )
            db.session.add(history)
            db.session.commit()
            
            logger.info(f"Analysis saved for user {current_user.username}: {result['category']} (confidence: {result['confidence']:.2%})")
            result['history_id'] = history.id
            
        except Exception as e:
            logger.error(f"Error saving to history: {str(e)}")
            db.session.rollback()
        
        # Prepare response
        response = {
            'success': True,
            'is_spam': result['is_spam'],
            'confidence': round(result['confidence'] * 100, 2),
            'probability_spam': round(result.get('probability_spam', result['confidence'] if result['is_spam'] else 1-result['confidence']) * 100, 2),
            'probability_ham': round(result.get('probability_ham', 1-result['confidence'] if result['is_spam'] else result['confidence']) * 100, 2),
            'category': result['category'],
            'explanation': result['explanation'],
            'risk_score': round(result.get('risk_score', result['confidence'] * 100), 2),
            'processing_time': result['processing_time'],
            'method': result.get('method', 'unknown'),
            'recommendations': result.get('recommendations', []),
            'detected_keywords': result.get('detected_keywords', []),
            'risk_factors': result.get('risk_factors', []),
            'history_id': result.get('history_id'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add warning if using fallback
        if not model or not vectorizer:
            response['warning'] = 'ML model not available, using rule-based analysis'
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': 'Analysis failed. Please try again.'}), 500

@analysis_bp.route('/analyze-batch', methods=['POST'])
@login_required
def analyze_batch():
    """Analyze multiple emails in batch"""
    
    try:
        data = request.get_json()
        
        if not data or 'emails' not in data:
            return jsonify({'error': 'No emails provided'}), 400
        
        emails = data['emails']
        
        if not isinstance(emails, list):
            return jsonify({'error': 'Emails must be a list'}), 400
        
        if len(emails) > 50:
            return jsonify({'error': 'Maximum 50 emails per batch'}), 400
        
        results = []
        spam_count = 0
        phishing_count = 0
        total_confidence = 0
        
        for i, email_data in enumerate(emails):
            subject = email_data.get('subject', '').strip()
            content = email_data.get('content', '').strip()
            
            if content:
                # Analyze email
                if model and vectorizer:
                    result = analyze_with_ml(f"{subject} {content}")
                    if not result:
                        result = analyze_with_rules(subject, content)
                else:
                    result = analyze_with_rules(subject, content)
                
                # Update counts
                if result['is_spam']:
                    spam_count += 1
                    if result['category'] == 'Phishing':
                        phishing_count += 1
                
                total_confidence += result['confidence']
                
                # Add to results
                results.append({
                    'id': i + 1,
                    'subject': subject[:100] if subject else '(No subject)',
                    'preview': content[:150] + '...' if len(content) > 150 else content,
                    'is_spam': result['is_spam'],
                    'confidence': round(result['confidence'] * 100, 2),
                    'category': result['category'],
                    'risk_score': round(result.get('risk_score', result['confidence'] * 100), 2)
                })
        
        # Calculate summary
        avg_confidence = (total_confidence / len(results)) if results else 0
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total': len(results),
                'spam_count': spam_count,
                'phishing_count': phishing_count,
                'legitimate_count': len(results) - spam_count,
                'spam_percentage': round((spam_count / len(results) * 100) if results else 0, 2),
                'avg_confidence': round(avg_confidence * 100, 2)
            },
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Batch analysis error: {str(e)}")
        return jsonify({'error': 'Batch analysis failed'}), 500

@analysis_bp.route('/model-status', methods=['GET'])
def model_status():
    """Check if ML model is loaded"""
    return jsonify({
        'model_loaded': model is not None,
        'vectorizer_loaded': vectorizer is not None,
        'using_ml': model is not None and vectorizer is not None,
        'metadata': model_metadata,
        'preprocessor_available': True
    }), 200

@analysis_bp.route('/reload-model', methods=['POST'])
@login_required
def reload_model():
    """Reload the ML model (admin only)"""
    
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        success = load_model()
        
        return jsonify({
            'success': success,
            'model_loaded': model is not None,
            'metadata': model_metadata,
            'message': 'Model reloaded successfully' if success else 'Model reload failed'
        }), 200
        
    except Exception as e:
        logger.error(f"Model reload error: {str(e)}")
        return jsonify({'error': 'Failed to reload model'}), 500

@analysis_bp.route('/extract-features', methods=['POST'])
@login_required
def extract_features():
    """Extract features from email without classification"""
    
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'error': 'Content is required'}), 400
        
        # Extract basic features
        words = content.split()
        sentences = content.count('.') + content.count('!') + content.count('?')
        
        features = {
            'length': len(content),
            'word_count': len(words),
            'sentence_count': sentences,
            'avg_word_length': sum(len(w) for w in words) / len(words) if words else 0,
            'caps_count': sum(1 for c in content if c.isupper()),
            'exclamation_count': content.count('!'),
            'question_count': content.count('?'),
            'url_count': content.count('http') + content.count('www'),
            'email_count': content.count('@'),
            'number_count': sum(c.isdigit() for c in content),
            'special_char_count': sum(1 for c in content if not c.isalnum() and not c.isspace())
        }
        
        return jsonify({
            'success': True,
            'features': features,
            'processed': preprocessor.preprocess(content)[:200] + '...'
        }), 200
        
    except Exception as e:
        logger.error(f"Feature extraction error: {str(e)}")
        return jsonify({'error': 'Feature extraction failed'}), 500

@analysis_bp.route('/quick-check', methods=['POST'])
def quick_check():
    """Quick spam check without authentication (limited)"""
    
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'error': 'Content is required'}), 400
        
        # Limit length for quick check
        if len(content) > 500:
            content = content[:500]
        
        # Use rule-based only for quick check
        result = analyze_with_rules('', content)
        
        return jsonify({
            'success': True,
            'is_spam': result['is_spam'],
            'confidence': round(result['confidence'] * 100, 2),
            'category': result['category'],
            'risk_score': round(result.get('risk_score', result['confidence'] * 100), 2),
            'warning': 'Quick check only - login for full analysis'
        }), 200
        
    except Exception as e:
        logger.error(f"Quick check error: {str(e)}")
        return jsonify({'error': 'Quick check failed'}), 500

@analysis_bp.route('/feedback/<int:history_id>', methods=['POST'])
@login_required
def submit_feedback(history_id):
    """Submit feedback on analysis accuracy"""
    
    try:
        data = request.get_json()
        
        if not data or 'correct' not in data:
            return jsonify({'error': 'No feedback provided'}), 400
        
        # Find history item
        history = AnalysisHistory.query.filter_by(
            id=history_id,
            user_id=current_user.id
        ).first()
        
        if not history:
            return jsonify({'error': 'History item not found'}), 404
        
        # Store feedback (you might want to add feedback field to model)
        logger.info(f"Feedback from user {current_user.username} for analysis {history_id}: {'correct' if data['correct'] else 'incorrect'}")
        
        return jsonify({
            'success': True,
            'message': 'Feedback received. Thank you for helping improve our system!'
        }), 200
        
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}")
        return jsonify({'error': 'Feedback submission failed'}), 500

@analysis_bp.route('/stats', methods=['GET'])
@login_required
def get_analysis_stats():
    """Get analysis statistics for current user"""
    
    try:
        # Get user's analyses
        analyses = AnalysisHistory.query.filter_by(user_id=current_user.id)
        
        total = analyses.count()
        spam = analyses.filter_by(is_spam=True).count()
        phishing = analyses.filter_by(category='Phishing').count()
        
        # Get recent activity
        recent = analyses.order_by(AnalysisHistory.created_at.desc()).limit(5).all()
        
        # Get daily stats for last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        daily = db.session.query(
            db.func.date(AnalysisHistory.created_at).label('date'),
            db.func.count().label('count'),
            db.func.sum(db.cast(AnalysisHistory.is_spam, db.Integer)).label('spam')
        ).filter(
            AnalysisHistory.user_id == current_user.id,
            AnalysisHistory.created_at >= thirty_days_ago
        ).group_by(
            db.func.date(AnalysisHistory.created_at)
        ).order_by(
            db.func.date(AnalysisHistory.created_at)
        ).all()
        
        return jsonify({
            'total_analyses': total,
            'spam_count': spam,
            'phishing_count': phishing,
            'legitimate_count': total - spam,
            'spam_percentage': round((spam / total * 100) if total > 0 else 0, 2),
            'recent': [{
                'id': a.id,
                'subject': a.email_subject,
                'category': a.category,
                'confidence': round(a.confidence * 100, 2) if a.confidence else 0,
                'created_at': a.created_at.isoformat()
            } for a in recent],
            'daily_stats': [{
                'date': str(d.date),
                'total': d.count,
                'spam': d.spam or 0
            } for d in daily]
        }), 200
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({'error': 'Failed to get statistics'}), 500

# Initialize model on module load
load_model()