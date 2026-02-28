"""
Authentication routes for user registration, login, and profile management
"""

from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from utils.database import db
from models.user import User, LoginAttempt, BlockedIP, UserSession
from utils.validators import validate_username, validate_email_address, validate_password
from datetime import datetime, timedelta
import logging
import re
import user_agents
import hashlib

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

def get_client_info():
    """Get client IP and user agent information"""
    # Get IP address (handling proxies)
    if request.headers.get('X-Forwarded-For'):
        ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip_address = request.headers.get('X-Real-IP')
    else:
        ip_address = request.remote_addr
    
    # Get user agent
    user_agent_string = request.headers.get('User-Agent', '')
    user_agent = user_agents.parse(user_agent_string)
    
    return {
        'ip_address': ip_address,
        'user_agent': user_agent_string,
        'browser': user_agent.browser.family,
        'os': user_agent.os.family,
        'device': user_agent.device.family
    }

def check_ip_blocked(ip_address):
    """Check if IP is blocked"""
    blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if blocked and blocked.is_blocked():
        logger.warning(f"Blocked IP attempted access: {ip_address}")
        return True, blocked.time_remaining()
    return False, 0

def record_login_attempt(username, email, ip_address, user_agent, success, failure_reason=None):
    """Record login attempt for security monitoring"""
    attempt = LoginAttempt(
        username=username,
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        failure_reason=failure_reason
    )
    db.session.add(attempt)
    
    # If failed attempt, check for brute force
    if not success:
        # Count failed attempts from this IP in last 15 minutes
        recent_failures = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.timestamp > datetime.utcnow() - timedelta(minutes=15)
        ).count()
        
        # Block IP after 10 failures
        if recent_failures >= 10:
            blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
            if not blocked:
                blocked = BlockedIP(
                    ip_address=ip_address,
                    reason=f"Too many failed login attempts ({recent_failures})",
                    blocked_until=datetime.utcnow() + timedelta(hours=2),
                    attempts_count=recent_failures
                )
                db.session.add(blocked)
                logger.warning(f"IP {ip_address} blocked for 2 hours due to {recent_failures} failed attempts")
            else:
                blocked.attempts_count = recent_failures
                blocked.blocked_until = datetime.utcnow() + timedelta(hours=2)
    
    db.session.commit()

def create_user_session(user, client_info):
    """Create a new user session"""
    # Generate session ID
    session_id = hashlib.sha256(
        f"{user.id}{client_info['ip_address']}{client_info['user_agent']}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()
    
    # Create session record
    user_session = UserSession(
        user_id=user.id,
        session_id=session_id,
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    
    db.session.add(user_session)
    db.session.commit()
    
    return session_id

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        client_info = get_client_info()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'full_name']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate username
        is_valid, msg = validate_username(data['username'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Validate email
        is_valid, email = validate_email_address(data['email'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Validate password
        is_valid, msg = validate_password(data['password'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Check if user exists
        if User.query.filter_by(username=data['username']).first():
            record_login_attempt(data['username'], email, client_info['ip_address'], 
                               client_info['user_agent'], False, 'Username already exists')
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            record_login_attempt(data['username'], email, client_info['ip_address'], 
                               client_info['user_agent'], False, 'Email already registered')
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create new user
        user = User(
            username=data['username'],
            email=email,
            full_name=data['full_name']
        )
        user.password = data['password']
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {user.username} from IP: {client_info['ip_address']}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        client_info = get_client_info()
        
        # Check if IP is blocked
        is_blocked, time_remaining = check_ip_blocked(client_info['ip_address'])
        if is_blocked:
            return jsonify({
                'error': 'Too many failed attempts',
                'message': f'IP blocked. Try again in {time_remaining} seconds',
                'blocked_until': time_remaining
            }), 403
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400
        
        username = data['username']
        password = data['password']
        remember = data.get('remember', False)
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not user.verify_password(password):
            # Record failed attempt
            record_login_attempt(username, username, client_info['ip_address'], 
                               client_info['user_agent'], False, 'Invalid credentials')
            
            # Check if user exists but password wrong
            if user:
                user.record_failed_attempt()
            
            logger.warning(f"Failed login attempt for {username} from IP: {client_info['ip_address']}")
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Check if account is locked
        if user.is_locked():
            return jsonify({
                'error': 'Account locked',
                'message': 'Too many failed attempts. Try again later.',
                'locked_until': user.locked_until.isoformat() if user.locked_until else None
            }), 403
        
        if not user.is_active:
            record_login_attempt(username, user.email, client_info['ip_address'], 
                               client_info['user_agent'], False, 'Account deactivated')
            return jsonify({'error': 'Account is deactivated. Please contact administrator.'}), 403
        
        # Record successful login
        record_login_attempt(username, user.email, client_info['ip_address'], 
                           client_info['user_agent'], True)
        
        # Update user login info
        user.update_login_info(client_info['ip_address'])
        
        # Create session
        session_id = create_user_session(user, client_info)
        
        # Login user with Flask-Login
        login_user(user, remember=remember)
        
        # Set session data
        session['user_id'] = user.id
        session['session_id'] = session_id
        session['login_time'] = datetime.utcnow().isoformat()
        
        logger.info(f"User logged in: {user.username} from IP: {client_info['ip_address']}")
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'session_id': session_id[:16] + '...',
            'client_info': {
                'ip': client_info['ip_address'],
                'browser': client_info['browser'],
                'os': client_info['os']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout user"""
    try:
        username = current_user.username
        
        # Remove session record
        if 'session_id' in session:
            UserSession.query.filter_by(session_id=session['session_id']).delete()
        
        # Logout user
        logout_user()
        session.clear()
        
        logger.info(f"User logged out: {username}")
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    """Get current user profile"""
    try:
        # Get active sessions count
        active_sessions = UserSession.query.filter_by(user_id=current_user.id).count()
        
        profile_data = current_user.to_dict(include_sensitive=True)
        profile_data['active_sessions'] = active_sessions
        
        return jsonify({'user': profile_data}), 200
        
    except Exception as e:
        logger.error(f"Profile fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        data = request.get_json()
        user = current_user
        
        # Update allowed fields
        allowed_fields = ['full_name', 'phone', 'bio', 'theme_preference', 'email_notifications']
        
        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])
        
        # Handle email update separately
        if 'email' in data and data['email'] != user.email:
            is_valid, email = validate_email_address(data['email'])
            if not is_valid:
                return jsonify({'error': 'Invalid email address'}), 400
            
            # Check if email is already taken
            existing = user.query.filter_by(email=email).first()
            if existing and existing.id != user.id:
                return jsonify({'error': 'Email already in use'}), 400
            
            user.email = email
            user.email_verified = False  # Require re-verification
        
        # Handle profile picture
        if 'profile_picture' in data:
            # In production, validate and save image
            user.profile_picture = data['profile_picture']
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Profile updated for user: {user.username}")
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Profile update error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Profile update failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        
        if not data or 'current_password' not in data or 'new_password' not in data:
            return jsonify({'error': 'Current and new password required'}), 400
        
        user = current_user
        
        # Verify current password
        if not user.verify_password(data['current_password']):
            logger.warning(f"Failed password change attempt for user: {user.username}")
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password
        is_valid, msg = validate_password(data['new_password'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Check if new password is same as old
        if user.verify_password(data['new_password']):
            return jsonify({'error': 'New password must be different from current password'}), 400
        
        # Update password
        user.password = data['new_password']
        user.password_changed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Password changed for user: {user.username}")
        
        # Invalidate all other sessions
        UserSession.query.filter(
            UserSession.user_id == user.id,
            UserSession.session_id != session.get('session_id', '')
        ).delete()
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Password change failed'}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Handle forgot password request"""
    try:
        data = request.get_json()
        client_info = get_client_info()
        
        if not data or 'email' not in data:
            return jsonify({'error': 'Email required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        # Always return success for security (prevents email enumeration)
        if user:
            # Generate reset token
            token = user.generate_reset_token()
            
            # In production, send email with reset link
            # For development, log it
            reset_link = f"http://localhost:5500/reset-password?token={token}"
            logger.info(f"Password reset link for {user.email}: {reset_link}")
            
            # TODO: Send email with reset link
            # send_password_reset_email(user.email, reset_link)
        
        return jsonify({
            'message': 'If your email is registered, you will receive a password reset link'
        }), 200
        
    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        return jsonify({'error': 'Request failed'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        client_info = get_client_info()
        
        if not data or 'token' not in data or 'new_password' not in data:
            return jsonify({'error': 'Token and new password required'}), 400
        
        # Verify token
        user = User.verify_reset_token(data['token'])
        
        if not user:
            logger.warning(f"Invalid reset token used from IP: {client_info['ip_address']}")
            return jsonify({'error': 'Invalid or expired token'}), 400
        
        # Validate new password
        is_valid, msg = validate_password(data['new_password'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Update password
        user.password = data['new_password']
        user.password_reset_token = None
        user.password_reset_expires = None
        user.password_changed_at = datetime.utcnow()
        
        # Invalidate all sessions
        UserSession.query.filter_by(user_id=user.id).delete()
        
        db.session.commit()
        
        logger.info(f"Password reset for user: {user.username} from IP: {client_info['ip_address']}")
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Verify user email address"""
    try:
        # Decode token
        # Implementation depends on your email verification system
        # This is a placeholder
        
        return jsonify({'message': 'Email verified successfully'}), 200
        
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}")
        return jsonify({'error': 'Email verification failed'}), 400

@auth_bp.route('/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Get all active sessions for current user"""
    try:
        sessions = UserSession.query.filter_by(user_id=current_user.id).all()
        
        return jsonify({
            'sessions': [s.to_dict() for s in sessions],
            'current_session': session.get('session_id', '')[:16] + '...'
        }), 200
        
    except Exception as e:
        logger.error(f"Session fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch sessions'}), 500

@auth_bp.route('/sessions/<session_id>', methods=['DELETE'])
@login_required
def revoke_session(session_id):
    """Revoke a specific session"""
    try:
        # Don't allow revoking current session
        if session_id == session.get('session_id'):
            return jsonify({'error': 'Cannot revoke current session'}), 400
        
        user_session = UserSession.query.filter_by(
            user_id=current_user.id,
            session_id=session_id
        ).first()
        
        if user_session:
            db.session.delete(user_session)
            db.session.commit()
            logger.info(f"Session {session_id[:8]} revoked for user {current_user.username}")
        
        return jsonify({'message': 'Session revoked successfully'}), 200
        
    except Exception as e:
        logger.error(f"Session revoke error: {str(e)}")
        return jsonify({'error': 'Failed to revoke session'}), 500

@auth_bp.route('/check-session', methods=['GET'])
@login_required
def check_session():
    """Check if session is valid"""
    return jsonify({
        'authenticated': True,
        'user': current_user.to_dict(),
        'session_id': session.get('session_id', '')[:16] + '...'
    }), 200

@auth_bp.route('/refresh-token', methods=['POST'])
@login_required
def refresh_token():
    """Refresh authentication token"""
    try:
        # Update session expiry
        session.permanent = True
        
        return jsonify({
            'message': 'Session refreshed',
            'expires_in': current_app.config.get('PERMANENT_SESSION_LIFETIME').total_seconds()
        }), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Failed to refresh session'}), 500

@auth_bp.route('/delete-account', methods=['DELETE'])
@login_required
def delete_account():
    """Delete user account"""
    try:
        data = request.get_json()
        
        if not data or 'password' not in data:
            return jsonify({'error': 'Password required'}), 400
        
        user = current_user
        
        # Verify password
        if not user.verify_password(data['password']):
            return jsonify({'error': 'Invalid password'}), 401
        
        # Store username for logging
        username = user.username
        
        # Delete user (cascades to all related data)
        db.session.delete(user)
        db.session.commit()
        
        # Logout
        logout_user()
        session.clear()
        
        logger.info(f"User account deleted: {username}")
        
        return jsonify({'message': 'Account deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Account deletion error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete account'}), 500