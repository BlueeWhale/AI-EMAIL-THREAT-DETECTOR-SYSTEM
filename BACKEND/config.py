import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class"""
    
    # Secret key for sessions - CHANGE THIS IN PRODUCTION!
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///instance/users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    REMEMBER_COOKIE_SECURE = True  # Set to False if not using HTTPS
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True  # Set to False if not using HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'eml'}
    
    # CORS settings - Add your frontend URLs here
    CORS_ORIGINS = [
        'http://localhost:5500',      # VS Code Live Server
        'http://127.0.0.1:5500',      # VS Code Live Server alternative
        'http://localhost:3000',      # React dev server
        'http://localhost:8000',      # Python HTTP server
        'http://127.0.0.1:8000',      # Python HTTP server alternative
        'http://localhost:5000',      # Flask itself
        'http://127.0.0.1:5000',      # Flask alternative
    ]
    CORS_SUPPORTS_CREDENTIALS = True
    
    # Logging
    LOG_FILE = 'logs/app.log'
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Model paths
    MODEL_PATH = os.environ.get('MODEL_PATH') or 'models/spam_model.pkl'
    VECTORIZER_PATH = os.environ.get('VECTORIZER_PATH') or 'models/tfidf_vectorizer.pkl'
    
    # Model training parameters
    MODEL_MAX_FEATURES = 5000
    MODEL_NGRAM_RANGE = (1, 2)
    MODEL_MIN_DF = 2
    MODEL_MAX_DF = 0.8
    MODEL_ALPHA = 0.1
    
    # Rate limiting (optional - requires flask-limiter)
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'False').lower() == 'true'
    RATELIMIT_DEFAULT = '100 per day, 10 per hour'
    RATELIMIT_STRATEGY = 'fixed-window'
    
    # Email settings (for password reset, etc.)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
    
    # Application settings
    APP_NAME = 'AI Email Threat Detector'
    APP_VERSION = '1.0.0'
    APP_DESCRIPTION = 'Machine Learning based email spam and phishing detection system'
    
    # Security
    BCRYPT_LOG_ROUNDS = 13
    TOKEN_EXPIRATION_DAYS = 30
    TOKEN_EXPIRATION_SECONDS = 86400  # 24 hours
    
    # Pagination
    DEFAULT_PAGE_SIZE = 10
    MAX_PAGE_SIZE = 100
    
    # Cache settings (optional - requires flask-caching)
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = 300
    
    @staticmethod
    def init_app(app):
        """Initialize application with this config"""
        # Create necessary directories
        os.makedirs('logs', exist_ok=True)
        os.makedirs('models', exist_ok=True)
        os.makedirs('instance', exist_ok=True)
        os.makedirs('uploads', exist_ok=True)
        os.makedirs('data', exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Less strict security for development
    REMEMBER_COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
    
    # More verbose logging
    LOG_LEVEL = 'DEBUG'
    
    # Allow all origins in development (be careful!)
    CORS_ORIGINS = ['*']


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Stricter security for production
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Production CORS - must be specific domains
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',') or [
        'https://yourdomain.com',
        'https://app.yourdomain.com'
    ]
    
    # Use PostgreSQL in production if available
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:password@localhost/dbname'


class DockerConfig(ProductionConfig):
    """Docker deployment configuration"""
    
    # Docker-specific settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://postgres:postgres@db:5432/spam_detector'
    
    # Docker often uses different ports
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',') or [
        'http://localhost:3000',
        'http://frontend:3000'
    ]


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}

# Get current configuration based on environment
def get_config():
    """Get the current configuration based on FLASK_ENV"""
    env = os.environ.get('FLASK_ENV', 'default')
    return config.get(env, config['default'])

# Initialize config
Config.init_app(None)  # Create directories