"""Database connection management for Lambda"""

import os
import json
import logging
from contextlib import contextmanager
from typing import Generator, Optional, Dict, Any

import boto3
from sqlalchemy import create_engine, event, pool
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database manager optimized for Lambda"""
    
    _instance: Optional['DatabaseManager'] = None
    _engine: Optional[Engine] = None
    _session_factory: Optional[sessionmaker] = None
    _connection_string: Optional[str] = None
    
    def __new__(cls) -> 'DatabaseManager':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._setup_database()
    
    def _get_connection_string(self) -> str:
        """Build connection string from environment"""
        if self._connection_string:
            return self._connection_string
        
        # Required environment variables
        db_host = os.environ['DB_HOST']
        db_name = os.environ['DB_NAME']
        
        # Optional with defaults
        db_port = os.environ.get('DB_PORT', '5432')
        db_user = os.environ.get('DB_USER', 'postgres')
        
        # Get password from Secrets Manager
        secret_arn = os.environ['DB_SECRET_ARN']
        
        try:
            secrets_client = boto3.client('secretsmanager')
            response = secrets_client.get_secret_value(SecretId=secret_arn)
            secret = json.loads(response['SecretString'])
            
            # Handle different secret formats
            db_password = (
                secret.get('password') or 
                secret.get('Password') or
                secret.get('db_password')
            )
            
            if not db_password:
                raise ValueError(f"Password not found in secret. Keys: {list(secret.keys())}")
            
            # Override with values from secret if present
            db_host = secret.get('host', db_host)
            db_port = str(secret.get('port', db_port))
            db_name = secret.get('dbname', db_name)
            db_user = secret.get('username', db_user)
            
        except Exception as e:
            logger.error(f"Failed to retrieve secret: {e}")
            raise
        
        self._connection_string = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        return self._connection_string
    
    def _setup_database(self) -> None:
        """Initialize database connection with Lambda-optimized settings"""
        connection_string = self._get_connection_string()
        
        # Lambda optimization: NullPool for connection per request
        # Avoids connection timeout issues in Lambda containers
        self._engine = create_engine(
            connection_string,
            poolclass=pool.NullPool,
            echo=os.getenv('DB_ECHO', 'false').lower() == 'true',
            connect_args={
                "connect_timeout": 5,
                "options": "-c statement_timeout=30000"  # 30 second query timeout
            }
        )
        
        self._session_factory = sessionmaker(
            bind=self._engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False  # Avoid lazy load issues
        )
        
        # Connection validation
        @event.listens_for(self._engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            connection_record.info['pid'] = os.getpid()
        
        @event.listens_for(self._engine, "checkout")
        def receive_checkout(dbapi_conn, connection_record, connection_proxy):
            pid = os.getpid()
            if connection_record.info['pid'] != pid:
                connection_record.connection = connection_proxy.connection = None
                raise pool.DisconnectedError(
                    "Connection record belongs to pid %s, attempting to check out in pid %s" %
                    (connection_record.info['pid'], pid)
                )
    
    def get_session(self) -> Session:
        """Get database session"""
        if not self._session_factory:
            self._setup_database()
        return self._session_factory()
    
    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Transactional scope with automatic cleanup"""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

# Singleton instance
db_manager = DatabaseManager()

# Convenience functions
def get_db_session() -> Session:
    """Get new database session"""
    return db_manager.get_session()

@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager for database operations"""
    with db_manager.session_scope() as session:
        yield session