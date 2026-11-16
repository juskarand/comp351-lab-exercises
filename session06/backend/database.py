"""
Session 6: Database Configuration

Same database setup as Session 5, but now we have two tables:
- users: User accounts with hashed passwords
- tasks: Tasks owned by specific users
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite database for development
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth_tasks.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Dependency that provides a database session.

    Used with FastAPI's Depends() for automatic session management.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
