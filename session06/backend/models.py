"""
Session 6: SQLAlchemy ORM Models with Relationships

This module adds user authentication concepts:
- User model with hashed passwords
- Task model with foreign key to user (ownership)
- One-to-many relationship: one user has many tasks

Key concepts:
- ForeignKey: Links tasks to users
- relationship: Enables ORM navigation between related objects
- back_populates: Two-way relationship navigation
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class User(Base):
    """
    User model for authentication.

    Attributes:
        id: Primary key
        email: Unique email address (used as username)
        hashed_password: Password hash (never store plain passwords!)
        is_active: Whether the user account is active
        tasks: Relationship to user's tasks
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)

    # Relationship: User -> Tasks (one-to-many)
    # back_populates links to the 'owner' attribute on Task
    tasks = relationship("Task", back_populates="owner")

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}')>"


class Task(Base):
    """
    Task model with user ownership.

    Each task belongs to exactly one user. The owner_id foreign key
    establishes this relationship at the database level.
    """
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    completed = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Foreign key: Links to users.id
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationship: Task -> User (many-to-one)
    owner = relationship("User", back_populates="tasks")

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', owner_id={self.owner_id})>"
