"""
Session 6 OAuth Supplement: Database Configuration

SQLAlchemy setup for the OAuth demonstration.
Uses SQLite by default (no Docker required), with optional PostgreSQL
via docker-compose for production-like environments.

DATABASE_URL can be overridden via environment variable to switch backends.
"""

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()

# SQLite by default; override with DATABASE_URL env var for PostgreSQL
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///./oauth_demo.db"
)

# SQLite needs check_same_thread=False for FastAPI's threaded access
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a database session.

    Yields a session and ensures it is closed after the request,
    even if an exception occurs.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
