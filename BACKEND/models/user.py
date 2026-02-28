"""
User models for authentication and data management
"""

from utils.database import db, login_manager, bcrypt
from flask_login import UserMixin
from datetime import datetime, timedelta
import jwt
from flask import current_app
import logging
import hashlib
import secrets

logger = logging.getLogger(__name__)

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    """User model for authentication and profile management"""
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Authentication fields
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Profile fields
    full_name = db.Column(db.String(100))
    profile_picture = db.Column(db.String(200), default='default.png')
    bio = db.Column(db.Text, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    
    # Status fields
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))  # IPv6 compatible
    last_activity = db.Column(db.DateTime)
    
    # Security fields
    login_count = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime)
    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    # API and tokens
    api_key = db.Column(db.String(64), unique=True, nullable=True)
    api_key_created = db.Column(db.DateTime, nullable=True)
    
    # Preferences
    email_notifications = db.Column(db.Boolean, default=True)
    theme_preference = db.Column(db.String(20), default='light')
    
    # Relationships
    analysis_history = db.relationship(
        'AnalysisHistory', 
        backref='user', 
        lazy='dynamic', 
        cascade='all, delete-orphan',
        order_by='desc(AnalysisHistory.created_at)'
    )
    
    # Indexes for better performance
    __table_args__ = (
        db.Index('idx_user_username_email', 'username', 'email'),
        db.Index('idx_user_created', 'created_at'),
        db.Index('idx_user_last_login', 'last_login'),
    )
    
    @property
    def password(self):
        """Prevent password from being accessed"""
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        """Set password hash with bcrypt"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def verify_password(self, password):
        """Verify password against hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def check_password_strength(self, password):
        """Check if password meets strength requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            return False, "Password must contain at least one special character"
        return True, "Password is strong"
    
    def update_login_info(self, ip_address=None):
        """Update user login information"""
        self.last_login = datetime.utcnow()
        self.last_login_ip = ip_address
        self.last_activity = datetime.utcnow()
        self.login_count += 1
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()
    
    def record_failed_attempt(self):
        """Record failed login attempt and lock account if needed"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
            logger.warning(f"Account locked for user {self.username} due to failed attempts")
        db.session.commit()
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def generate_reset_token(self, expires_in=3600):
        """Generate password reset token"""
        try:
            # Create token
            payload = {
                'user_id': self.id,
                'type': 'password_reset',
                'exp': datetime.utcnow() + timedelta(seconds=expires_in),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(
                payload,
                current_app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            
            # Store in database for verification
            self.password_reset_token = hashlib.sha256(token.encode()).hexdigest()
            self.password_reset_expires = datetime.utcnow() + timedelta(seconds=expires_in)
            db.session.commit()
            
            return token
        except Exception as e:
            logger.error(f"Error generating reset token: {e}")
            return None
    
    @staticmethod
    def verify_reset_token(token):
        """Verify password reset token"""
        try:
            # Decode token
            payload = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            
            if payload.get('type') != 'password_reset':
                return None
            
            # Get user
            user = User.query.get(payload['user_id'])
            if not user:
                return None
            
            # Verify token hash
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if user.password_reset_token != token_hash:
                return None
            
            # Check expiration
            if user.password_reset_expires < datetime.utcnow():
                return None
            
            return user
            
        except jwt.ExpiredSignatureError:
            logger.warning("Reset token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid reset token")
            return None
        except Exception as e:
            logger.error(f"Error verifying reset token: {e}")
            return None
    
    def generate_api_key(self):
        """Generate new API key for user"""
        self.api_key = secrets.token_urlsafe(32)
        self.api_key_created = datetime.utcnow()
        db.session.commit()
        return self.api_key
    
    def revoke_api_key(self):
        """Revoke current API key"""
        self.api_key = None
        self.api_key_created = None
        db.session.commit()
    
    def verify_api_key(self, api_key):
        """Verify API key"""
        return self.api_key and secrets.compare_digest(self.api_key, api_key)
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary (safe version)"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'profile_picture': self.profile_picture,
            'bio': self.bio,
            'phone': self.phone,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'email_verified': self.email_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'login_count': self.login_count,
            'email_notifications': self.email_notifications,
            'theme_preference': self.theme_preference
        }
        
        if include_sensitive:
            data.update({
                'last_login_ip': self.last_login_ip,
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None,
                'password_changed_at': self.password_changed_at.isoformat() if self.password_changed_at else None,
                'api_key': self.api_key,
                'api_key_created': self.api_key_created.isoformat() if self.api_key_created else None
            })
        
        return data
    
    def get_analysis_stats(self):
        """Get user's analysis statistics"""
        total = self.analysis_history.count()
        spam = self.analysis_history.filter_by(is_spam=True).count()
        phishing = self.analysis_history.filter_by(category='Phishing').count()
        
        return {
            'total_analyses': total,
            'spam_count': spam,
            'phishing_count': phishing,
            'legitimate_count': total - spam,
            'spam_percentage': round((spam / total * 100), 2) if total > 0 else 0
        }
    
    def get_recent_activity(self, limit=10):
        """Get user's recent activity"""
        return self.analysis_history.limit(limit).all()
    
    def __repr__(self):
        return f'<User {self.username} (ID: {self.id})>'


class AnalysisHistory(db.Model):
    """Store email analysis history for users"""
    __tablename__ = 'analysis_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Email content
    email_subject = db.Column(db.String(200))
    email_content = db.Column(db.Text)
    email_from = db.Column(db.String(200), nullable=True)
    email_to = db.Column(db.String(200), nullable=True)
    email_date = db.Column(db.DateTime, nullable=True)
    
    # Analysis results
    is_spam = db.Column(db.Boolean)
    confidence = db.Column(db.Float)
    probability_spam = db.Column(db.Float)
    probability_ham = db.Column(db.Float)
    category = db.Column(db.String(50))
    explanation = db.Column(db.Text)
    
    # Analysis metadata
    processing_time = db.Column(db.Float)  # Time taken to analyze in seconds
    model_version = db.Column(db.String(20), default='1.0')
    
    # Request metadata
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Additional data
    detected_keywords = db.Column(db.Text, nullable=True)  # JSON string of detected keywords
    risk_factors = db.Column(db.Text, nullable=True)  # JSON string of risk factors
    recommendations = db.Column(db.Text, nullable=True)  # JSON string of recommendations
    
    # Indexes
    __table_args__ = (
        db.Index('idx_history_user_date', 'user_id', 'created_at'),
        db.Index('idx_history_category', 'category'),
        db.Index('idx_history_spam', 'is_spam'),
    )
    
    def to_dict(self, full_content=False):
        """Convert history item to dictionary"""
        import json
        
        data = {
            'id': self.id,
            'email_subject': self.email_subject,
            'email_preview': self.email_content[:200] + '...' if self.email_content and len(self.email_content) > 200 else self.email_content,
            'email_from': self.email_from,
            'email_to': self.email_to,
            'email_date': self.email_date.isoformat() if self.email_date else None,
            'is_spam': self.is_spam,
            'confidence': round(self.confidence * 100, 2) if self.confidence else 0,
            'probability_spam': round(self.probability_spam * 100, 2) if self.probability_spam else 0,
            'probability_ham': round(self.probability_ham * 100, 2) if self.probability_ham else 0,
            'category': self.category,
            'explanation': self.explanation,
            'processing_time': round(self.processing_time, 3) if self.processing_time else None,
            'model_version': self.model_version,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        # Include full content if requested
        if full_content:
            data['email_content'] = self.email_content
            data['detected_keywords'] = json.loads(self.detected_keywords) if self.detected_keywords else []
            data['risk_factors'] = json.loads(self.risk_factors) if self.risk_factors else []
            data['recommendations'] = json.loads(self.recommendations) if self.recommendations else []
        
        return data
    
    def __repr__(self):
        return f'<Analysis {self.id}: {self.email_subject} - Spam: {self.is_spam}>'


class LoginAttempt(db.Model):
    """Track login attempts for security monitoring"""
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), index=True)
    email = db.Column(db.String(120), index=True)
    ip_address = db.Column(db.String(45), index=True)
    user_agent = db.Column(db.String(200))
    success = db.Column(db.Boolean, default=False)
    failure_reason = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_login_ip_time', 'ip_address', 'timestamp'),
        db.Index('idx_login_username_time', 'username', 'timestamp'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'ip_address': self.ip_address,
            'success': self.success,
            'failure_reason': self.failure_reason,
            'timestamp': self.timestamp.isoformat()
        }
    
    def __repr__(self):
        return f'<LoginAttempt {self.username} - Success: {self.success}>'


class BlockedIP(db.Model):
    """Track blocked IP addresses for security"""
    __tablename__ = 'blocked_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(200))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_until = db.Column(db.DateTime)
    attempts_count = db.Column(db.Integer, default=0)
    
    def is_blocked(self):
        """Check if IP is currently blocked"""
        if not self.blocked_until:
            return False
        return datetime.utcnow() < self.blocked_until
    
    def time_remaining(self):
        """Get time remaining for block"""
        if not self.is_blocked():
            return 0
        remaining = self.blocked_until - datetime.utcnow()
        return int(remaining.total_seconds())
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat(),
            'blocked_until': self.blocked_until.isoformat() if self.blocked_until else None,
            'is_blocked': self.is_blocked(),
            'time_remaining': self.time_remaining(),
            'attempts_count': self.attempts_count
        }
    
    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'


class UserSession(db.Model):
    """Track active user sessions"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    session_id = db.Column(db.String(128), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='sessions')
    
    def is_active(self):
        """Check if session is still active"""
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        # Session timeout after 24 hours of inactivity
        if self.last_activity < datetime.utcnow() - timedelta(hours=24):
            return False
        return True
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id[:10] + '...',  # Truncate for security
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active()
        }
    
    def __repr__(self):
        return f'<UserSession {self.user_id} - {self.session_id[:8]}>'