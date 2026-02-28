#!/usr/bin/env python
"""
AI Email Threat Detector - Main Application
A Flask-based backend for email spam and phishing detection
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from flask import Flask, jsonify, request, send_from_directory, render_template_string
from flask_cors import CORS
from datetime import datetime, timedelta
import traceback
import platform
import psutil
import socket

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import configuration
try:
    from config import get_config
except ImportError as e:
    print(f"❌ Error importing config: {e}")
    print("Make sure config.py exists in the project root")
    sys.exit(1)

# Import database utilities
try:
    from utils.database import init_db, db, check_database_health, get_db_stats
    from utils.database import init_db_with_retry
except ImportError as e:
    print(f"❌ Error importing database utils: {e}")
    print("Make sure utils/database.py exists")
    sys.exit(1)

# Import models
try:
    from models.user import User, AnalysisHistory
except ImportError as e:
    print(f"❌ Error importing models: {e}")
    print("Make sure models/user.py exists")
    sys.exit(1)

# Create Flask app
app = Flask(__name__, 
            static_folder='static',
            static_url_path='/static',
            instance_relative_config=True)

# Load configuration
try:
    app.config.from_object(get_config())
    print("✅ Configuration loaded successfully")
except Exception as e:
    print(f"❌ Error loading configuration: {e}")
    print("Using default configuration")
    app.config['SECRET_KEY'] = 'dev-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(app):
    """Setup comprehensive logging configuration"""
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
        print("📁 Created logs directory")
    
    # Set log level from config
    log_level = app.config.get('LOG_LEVEL', 'INFO')
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Log format
    detailed_format = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(name)20s | %(filename)20s:%(lineno)-4d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_format = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # 1. Rotating File Handler - Main application log
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(detailed_format)
    file_handler.setLevel(numeric_level)
    root_logger.addHandler(file_handler)
    
    # 2. Timed Rotating File Handler - Daily logs
    daily_handler = TimedRotatingFileHandler(
        'logs/app_daily.log',
        when='midnight',
        interval=1,
        backupCount=30  # Keep 30 days of logs
    )
    daily_handler.setFormatter(detailed_format)
    daily_handler.setLevel(numeric_level)
    root_logger.addHandler(daily_handler)
    
    # 3. Error File Handler - Separate file for errors only
    error_handler = RotatingFileHandler(
        'logs/error.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    error_handler.setFormatter(detailed_format)
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)
    
    # 4. Console Handler - For development
    if app.debug or app.config.get('LOG_TO_CONSOLE', True):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(simple_format)
        console_handler.setLevel(numeric_level)
        root_logger.addHandler(console_handler)
    
    # Set levels for third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # Log startup information
    app.logger.info('=' * 90)
    app.logger.info(f"🚀 {app.config.get('APP_NAME', 'AI Email Threat Detector')} Started")
    app.logger.info(f"📅 Startup Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    app.logger.info(f"🔧 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    app.logger.info(f"📊 Log Level: {log_level}")
    app.logger.info(f"📁 Log File: logs/app.log")
    app.logger.info(f"🐍 Python: {platform.python_version()}")
    app.logger.info(f"💻 Host: {socket.gethostname()}")
    app.logger.info('=' * 90)

# Setup logging
setup_logging(app)

# ============================================================================
# EXTENSIONS INITIALIZATION
# ============================================================================

# Initialize CORS
CORS(app, 
     origins=app.config.get('CORS_ORIGINS', ['*']),
     supports_credentials=app.config.get('CORS_SUPPORTS_CREDENTIALS', True),
     allow_headers=['Content-Type', 'Authorization'])

# Initialize database with retry
try:
    init_db_with_retry(app, max_retries=3)
    app.logger.info("✅ Database initialized successfully")
except Exception as e:
    app.logger.error(f"❌ Database initialization failed: {str(e)}")
    app.logger.error(traceback.format_exc())

# ============================================================================
# BLUEPRINTS REGISTRATION
# ============================================================================

def register_blueprints(app):
    """Register all blueprints"""
    try:
        # Import blueprints
        from routes.auth import auth_bp
        from routes.analysis import analysis_bp
        from routes.history import history_bp
        
        # Register blueprints with URL prefixes
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
        app.register_blueprint(history_bp, url_prefix='/api/history')
        
        app.logger.info("✅ Blueprints registered successfully")
        app.logger.info("   • /api/auth - Authentication endpoints")
        app.logger.info("   • /api/analysis - Email analysis endpoints")
        app.logger.info("   • /api/history - History management endpoints")
        
    except ImportError as e:
        app.logger.error(f"❌ Blueprint import error: {e}")
        app.logger.error("Make sure route files exist in the routes directory")
    except Exception as e:
        app.logger.error(f"❌ Blueprint registration error: {str(e)}")
        app.logger.error(traceback.format_exc())

# Register blueprints
register_blueprints(app)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        app.logger.warning(f"400 Bad Request: {request.path} - {request.remote_addr}")
        return jsonify({
            'success': False,
            'error': 'Bad Request',
            'message': str(error.description) if hasattr(error, 'description') else 'Invalid request',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        app.logger.warning(f"401 Unauthorized: {request.path} - {request.remote_addr}")
        return jsonify({
            'success': False,
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        app.logger.warning(f"403 Forbidden: {request.path} - {request.remote_addr}")
        return jsonify({
            'success': False,
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        app.logger.info(f"404 Not Found: {request.path} - {request.remote_addr}")
        return jsonify({
            'success': False,
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        app.logger.warning(f"405 Method Not Allowed: {request.method} {request.path}")
        return jsonify({
            'success': False,
            'error': 'Method Not Allowed',
            'message': f'The method {request.method} is not allowed for this endpoint',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 405
    
    @app.errorhandler(429)
    def too_many_requests(error):
        app.logger.warning(f"429 Rate Limit: {request.remote_addr} - {request.path}")
        return jsonify({
            'success': False,
            'error': 'Too Many Requests',
            'message': 'Rate limit exceeded. Please try again later.',
            'retry_after': error.description if hasattr(error, 'description') else 60,
            'timestamp': datetime.utcnow().isoformat()
        }), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.error(f"500 Internal Server Error: {request.path}")
        app.logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    
    @app.errorhandler(503)
    def service_unavailable(error):
        app.logger.error(f"503 Service Unavailable")
        return jsonify({
            'success': False,
            'error': 'Service Unavailable',
            'message': 'The service is temporarily unavailable. Please try again later.',
            'timestamp': datetime.utcnow().isoformat()
        }), 503

# Register error handlers
register_error_handlers(app)

# ============================================================================
# REQUEST/RESPONSE HANDLERS
# ============================================================================

@app.before_request
def before_request():
    """Log each request"""
    # Skip logging for static files
    if request.path.startswith('/static'):
        return
    
    app.logger.debug(f"➡️ {request.method} {request.path} - {request.remote_addr}")

@app.after_request
def after_request(response):
    """Add headers to all responses"""
    # Add security headers
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'DENY')
    response.headers.add('X-XSS-Protection', '1; mode=block')
    response.headers.add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    
    # Log response status
    if not request.path.startswith('/static'):
        app.logger.debug(f"⬅️ {response.status_code} {request.path}")
    
    return response

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_uptime():
    """Get application uptime"""
    if not hasattr(app, '_start_time'):
        app._start_time = datetime.utcnow()
    
    uptime = datetime.utcnow() - app._start_time
    days = uptime.days
    hours = uptime.seconds // 3600
    minutes = (uptime.seconds % 3600) // 60
    seconds = uptime.seconds % 60
    
    return {
        'days': days,
        'hours': hours,
        'minutes': minutes,
        'seconds': seconds,
        'string': f"{days}d {hours}h {minutes}m {seconds}s"
    }

def get_system_info():
    """Get system information"""
    try:
        return {
            'python_version': platform.python_version(),
            'platform': platform.platform(),
            'hostname': socket.gethostname(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),
            'memory_available': round(psutil.virtual_memory().available / (1024**3), 2),
            'disk_usage': round(psutil.disk_usage('/').used / (1024**3), 2),
            'disk_free': round(psutil.disk_usage('/').free / (1024**3), 2)
        }
    except:
        return {'error': 'Could not get system info'}

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Root endpoint - API information"""
    return jsonify({
        'success': True,
        'name': app.config.get('APP_NAME', 'AI Email Threat Detector'),
        'version': app.config.get('APP_VERSION', '1.0.0'),
        'description': app.config.get('APP_DESCRIPTION', 'Email spam and phishing detection API'),
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'documentation': {
            'health': '/health',
            'auth': {
                'register': 'POST /api/auth/register',
                'login': 'POST /api/auth/login',
                'logout': 'POST /api/auth/logout',
                'profile': 'GET /api/auth/profile'
            },
            'analysis': {
                'analyze': 'POST /api/analysis/analyze',
                'batch': 'POST /api/analysis/analyze-batch',
                'quick': 'POST /api/analysis/quick-check'
            },
            'history': {
                'list': 'GET /api/history/',
                'details': 'GET /api/history/<id>',
                'stats': 'GET /api/history/stats'
            }
        }
    }), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    
    # Check database health
    db_health = check_database_health()
    
    # Check model status
    model_loaded = False
    try:
        from routes.analysis import model, vectorizer
        model_loaded = model is not None and vectorizer is not None
    except:
        pass
    
    health_status = {
        'success': True,
        'status': 'healthy' if db_health['status'] == 'healthy' else 'degraded',
        'timestamp': datetime.utcnow().isoformat(),
        'version': app.config.get('APP_VERSION', '1.0.0'),
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'database': db_health,
        'model': {
            'loaded': model_loaded
        },
        'uptime': get_uptime(),
        'system': get_system_info()
    }
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code

@app.route('/stats', methods=['GET'])
def stats():
    """Get application statistics"""
    try:
        # Get database stats
        db_stats = get_db_stats()
        
        # Get request stats from logs (simplified)
        request_count = 0
        try:
            with open('logs/app.log', 'r') as f:
                for line in f:
                    if '➡️' in line or '⬅️' in line:
                        request_count += 1
        except:
            pass
        
        return jsonify({
            'success': True,
            'database': db_stats,
            'requests': {
                'total_logged': request_count
            },
            'uptime': get_uptime(),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Stats error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Could not get statistics'
        }), 500

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    try:
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )
    except:
        return '', 204

@app.route('/robots.txt')
def robots():
    """Serve robots.txt"""
    return "User-agent: *\nDisallow: /api/\nAllow: /", 200

# ============================================================================
# CLI COMMANDS
# ============================================================================

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database"""
    from utils.database import init_db
    init_db(app)
    print("✅ Database initialized")

@app.cli.command('create-admin')
def create_admin_command():
    """Create admin user"""
    from models.user import User
    from getpass import getpass
    
    username = input("Username: ")
    email = input("Email: ")
    password = getpass("Password: ")
    
    user = User(
        username=username,
        email=email,
        full_name="Administrator",
        is_admin=True,
        is_verified=True
    )
    user.password = password
    
    db.session.add(user)
    db.session.commit()
    
    print(f"✅ Admin user '{username}' created")

@app.cli.command('cleanup')
def cleanup_command():
    """Clean up old records"""
    from utils.database import cleanup_old_records
    
    days = input("Delete records older than (days) [30]: ")
    try:
        days = int(days) if days else 30
        result = cleanup_old_records(days)
        print(f"✅ Deleted {result['analyses_deleted']} analysis records")
        print(f"✅ Deleted {result['logins_deleted']} login attempts")
    except ValueError:
        print("❌ Invalid number")

@app.cli.command('list-users')
def list_users_command():
    """List all users"""
    users = User.query.all()
    print(f"\n📋 Users ({len(users)}):")
    print("-" * 60)
    for user in users:
        print(f"ID: {user.id} | {user.username} | {user.email} | Admin: {user.is_admin} | Active: {user.is_active}")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    """Run the application"""
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    host = os.environ.get('HOST', '0.0.0.0')
    
    # Print startup banner
    print("\n" + "=" * 70)
    print(f"🚀 {app.config.get('APP_NAME', 'AI Email Threat Detector')}")
    print("=" * 70)
    print(f"📡 Server: http://{host}:{port}")
    print(f"🔧 Debug mode: {'ON' if debug else 'OFF'}")
    print(f"📊 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🐍 Python: {platform.python_version()}")
    print("-" * 70)
    print(f"📡 Endpoints:")
    print(f"   • Home: http://localhost:{port}/")
    print(f"   • Health: http://localhost:{port}/health")
    print(f"   • Auth: http://localhost:{port}/api/auth/")
    print(f"   • Analysis: http://localhost:{port}/api/analysis/")
    print(f"   • History: http://localhost:{port}/api/history/")
    print("-" * 70)
    print(f"📝 Log file: logs/app.log")
    print(f"📁 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print("=" * 70 + "\n")
    
    # Store start time
    app._start_time = datetime.utcnow()
    
    # Run the app
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
