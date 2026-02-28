"""
Database connection and management utilities
"""

import os
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from sqlalchemy import event, inspect
from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLite3Connection
from datetime import datetime
import time

# Configure logging
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()

@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints and optimize SQLite"""
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        # Enable foreign keys
        cursor.execute("PRAGMA foreign_keys=ON")
        # Better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        # Faster reads
        cursor.execute("PRAGMA synchronous=NORMAL")
        # Cache size in KB
        cursor.execute("PRAGMA cache_size=10000")
        # Temp store in memory
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()
        logger.debug("SQLite optimizations applied")

def init_db(app):
    """Initialize database with app context"""
    try:
        # Initialize extensions with app
        db.init_app(app)
        login_manager.init_app(app)
        bcrypt.init_app(app)
        
        # Configure login manager
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
        login_manager.login_message_category = 'info'
        login_manager.refresh_view = 'auth.login'
        login_manager.needs_refresh_message = 'Session expired. Please login again.'
        login_manager.needs_refresh_message_category = 'info'
        
        # Create tables if they don't exist
        with app.app_context():
            # Check if tables exist
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            # Create tables
            db.create_all()
            
            # Log which tables were created
            new_tables = set(inspector.get_table_names()) - set(existing_tables)
            if new_tables:
                logger.info(f"Created new tables: {', '.join(new_tables)}")
            else:
                logger.info("Database tables already exist")
            
            # Create default admin user if no users exist
            create_default_admin(app)
            
            # Log database location
            db_path = app.config['SQLALCHEMY_DATABASE_URI']
            logger.info(f"Database connected: {db_path}")
            
            # Run health check
            health = check_database_health()
            if health['status'] == 'healthy':
                logger.info("Database health check passed")
            else:
                logger.warning(f"Database health check warning: {health['message']}")
            
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

def create_default_admin(app):
    """Create default admin user if no users exist"""
    try:
        from models.user import User
        
        # Check if any user exists
        if User.query.count() == 0:
            logger.info("No users found. Creating default users...")
            
            # Create admin user
            admin = User(
                username='admin',
                email='admin@example.com',
                full_name='System Administrator',
                is_admin=True,
                is_active=True,
                is_verified=True,
                email_verified=True
            )
            admin.password = 'Admin123!'  # This will be hashed by the setter
            
            # Create regular test user
            test_user = User(
                username='testuser',
                email='test@example.com',
                full_name='Test User',
                is_admin=False,
                is_active=True,
                is_verified=True,
                email_verified=True
            )
            test_user.password = 'Test123!'
            
            # Add to database
            db.session.add(admin)
            db.session.add(test_user)
            db.session.commit()
            
            logger.info("Default users created successfully")
            logger.info("Admin credentials - Username: admin, Password: Admin123!")
            logger.info("Test credentials - Username: testuser, Password: Test123!")
        else:
            logger.info(f"Database already has {User.query.count()} users")
            
    except Exception as e:
        logger.error(f"Error creating default users: {str(e)}")
        db.session.rollback()

def get_db_stats():
    """Get database statistics"""
    try:
        from models.user import User, AnalysisHistory, LoginAttempt, BlockedIP
        
        # Get table counts
        stats = {
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'admin_users': User.query.filter_by(is_admin=True).count(),
            'verified_users': User.query.filter_by(is_verified=True).count(),
            'total_analyses': AnalysisHistory.query.count(),
            'spam_analyses': AnalysisHistory.query.filter_by(is_spam=True).count(),
            'phishing_analyses': AnalysisHistory.query.filter_by(category='Phishing').count(),
            'legitimate_analyses': AnalysisHistory.query.filter_by(is_spam=False).count(),
            'total_login_attempts': LoginAttempt.query.count(),
            'failed_logins': LoginAttempt.query.filter_by(success=False).count(),
            'blocked_ips': BlockedIP.query.count()
        }
        
        # Get database file size for SQLite
        db_uri = db.engine.url
        if db_uri.drivername == 'sqlite':
            db_path = db_uri.database
            if os.path.exists(db_path):
                stats['db_size_mb'] = round(os.path.getsize(db_path) / (1024 * 1024), 2)
        
        return stats
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        return {}

def backup_database(app):
    """Create a backup of the database"""
    try:
        import shutil
        from datetime import datetime
        
        # Get database path
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
            
            # Create backup directory
            backup_dir = 'backups'
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(backup_dir, f'db_backup_{timestamp}.db')
            
            # Copy database file
            if os.path.exists(db_path):
                shutil.copy2(db_path, backup_path)
                
                # Compress backup
                import gzip
                with open(backup_path, 'rb') as f_in:
                    with gzip.open(f'{backup_path}.gz', 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Remove uncompressed backup
                os.remove(backup_path)
                
                logger.info(f"Database backed up to {backup_path}.gz")
                return f'{backup_path}.gz'
            else:
                logger.warning(f"Database file not found at {db_path}")
                return None
        else:
            logger.warning("Backup only supported for SQLite databases")
            return None
            
    except Exception as e:
        logger.error(f"Error backing up database: {str(e)}")
        return None

def restore_database(backup_path, app):
    """Restore database from backup"""
    try:
        import shutil
        import gzip
        
        # Get current database path
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            current_db = db_uri.replace('sqlite:///', '')
            
            # Check if backup is compressed
            if backup_path.endswith('.gz'):
                # Decompress
                with gzip.open(backup_path, 'rb') as f_in:
                    with open(current_db, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                # Verify backup exists
                if not os.path.exists(backup_path):
                    logger.error(f"Backup file not found: {backup_path}")
                    return False
                
                # Copy backup
                shutil.copy2(backup_path, current_db)
            
            logger.info(f"Database restored from {backup_path}")
            return True
        else:
            logger.warning("Restore only supported for SQLite databases")
            return False
            
    except Exception as e:
        logger.error(f"Error restoring database: {str(e)}")
        return False

def cleanup_old_records(days=30):
    """Clean up analysis records older than specified days"""
    try:
        from models.user import AnalysisHistory, LoginAttempt
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Delete old analysis records
        deleted_analyses = AnalysisHistory.query.filter(
            AnalysisHistory.created_at < cutoff_date
        ).delete()
        
        # Delete old login attempts
        deleted_logins = LoginAttempt.query.filter(
            LoginAttempt.timestamp < cutoff_date
        ).delete()
        
        db.session.commit()
        
        logger.info(f"Cleaned up {deleted_analyses} analysis records and {deleted_logins} login attempts older than {days} days")
        return {
            'analyses_deleted': deleted_analyses,
            'logins_deleted': deleted_logins
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up old records: {str(e)}")
        db.session.rollback()
        return {'analyses_deleted': 0, 'logins_deleted': 0}

def get_user_activity_summary(user_id):
    """Get activity summary for a specific user"""
    try:
        from models.user import AnalysisHistory
        from datetime import datetime, timedelta
        
        # Time periods
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(weeks=1)
        month_ago = now - timedelta(days=30)
        
        # Query counts
        summary = {
            'last_24h': AnalysisHistory.query.filter(
                AnalysisHistory.user_id == user_id,
                AnalysisHistory.created_at >= day_ago
            ).count(),
            
            'last_7d': AnalysisHistory.query.filter(
                AnalysisHistory.user_id == user_id,
                AnalysisHistory.created_at >= week_ago
            ).count(),
            
            'last_30d': AnalysisHistory.query.filter(
                AnalysisHistory.user_id == user_id,
                AnalysisHistory.created_at >= month_ago
            ).count(),
            
            'total': AnalysisHistory.query.filter_by(user_id=user_id).count(),
            
            'spam_count': AnalysisHistory.query.filter_by(
                user_id=user_id, 
                is_spam=True
            ).count(),
            
            'phishing_count': AnalysisHistory.query.filter_by(
                user_id=user_id, 
                category='Phishing'
            ).count()
        }
        
        # Get last analysis
        last = AnalysisHistory.query.filter_by(user_id=user_id).order_by(
            AnalysisHistory.created_at.desc()
        ).first()
        
        if last:
            summary['last_analysis'] = {
                'id': last.id,
                'subject': last.email_subject,
                'category': last.category,
                'created_at': last.created_at.isoformat()
            }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error getting user activity summary: {str(e)}")
        return {}

def execute_raw_query(query, params=None):
    """Execute a raw SQL query safely"""
    try:
        if params:
            result = db.session.execute(query, params)
        else:
            result = db.session.execute(query)
        
        db.session.commit()
        return result
        
    except Exception as e:
        logger.error(f"Error executing raw query: {str(e)}")
        db.session.rollback()
        return None

def check_database_health():
    """Check if database is accessible and working"""
    try:
        start_time = time.time()
        
        # Try a simple query
        from models.user import User
        count = User.query.count()
        
        query_time = time.time() - start_time
        
        # Check disk space for SQLite
        db_uri = db.engine.url
        db_info = {}
        
        if db_uri.drivername == 'sqlite':
            db_path = db_uri.database
            if os.path.exists(db_path):
                size = os.path.getsize(db_path)
                size_mb = size / (1024 * 1024)
                db_info = {
                    'path': db_path,
                    'size_mb': round(size_mb, 2),
                    'exists': True
                }
                
                # Warn if database is getting large
                if size_mb > 100:  # 100MB
                    logger.warning(f"Database size is {size_mb:.2f}MB, consider cleanup")
        else:
            db_info = {
                'type': db_uri.drivername,
                'database': db_uri.database
            }
        
        return {
            'status': 'healthy',
            'message': 'Database connection successful',
            'user_count': count,
            'query_time_ms': round(query_time * 1000, 2),
            'database': db_info
        }
        
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return {
            'status': 'unhealthy',
            'message': str(e)
        }

def init_db_with_retry(app, max_retries=3):
    """Initialize database with retry logic"""
    for attempt in range(max_retries):
        try:
            init_db(app)
            logger.info(f"Database initialized successfully on attempt {attempt + 1}")
            return True
        except Exception as e:
            logger.warning(f"Database init attempt {attempt + 1} failed: {str(e)}")
            if attempt < max_retries - 1:
                import time
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logger.error("All database initialization attempts failed")
                raise
    
    return False

def vacuum_database():
    """Vacuum SQLite database to reclaim space"""
    try:
        db_uri = db.engine.url
        if db_uri.drivername == 'sqlite':
            logger.info("Starting database vacuum...")
            db.session.execute("VACUUM")
            logger.info("Database vacuum completed")
            return True
        else:
            logger.warning("Vacuum only supported for SQLite databases")
            return False
    except Exception as e:
        logger.error(f"Error vacuuming database: {str(e)}")
        return False

def get_table_info():
    """Get information about all tables"""
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        table_info = []
        for table in tables:
            columns = inspector.get_columns(table)
            indexes = inspector.get_indexes(table)
            
            # Get row count
            result = db.session.execute(f"SELECT COUNT(*) FROM {table}")
            row_count = result.scalar()
            
            table_info.append({
                'name': table,
                'columns': len(columns),
                'indexes': len(indexes),
                'rows': row_count,
                'column_names': [c['name'] for c in columns]
            })
        
        return table_info
    except Exception as e:
        logger.error(f"Error getting table info: {str(e)}")
        return []

# Import timedelta for cleanup function
from datetime import timedelta