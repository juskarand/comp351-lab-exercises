"""
Session 6: JWT Authentication API

This module demonstrates secure authentication with JWT tokens:
- User registration with password hashing
- Login to receive JWT access token
- Protected endpoints requiring valid token
- User-scoped data (each user sees only their tasks)

Run with: uvicorn main:app --reload
Test at: http://localhost:8000/docs (Swagger UI)

Authentication Flow:
1. Register: POST /register with JSON email and password
2. Login: POST /login with JSON credentials -> receive JWT
3. Access: Include "Authorization: Bearer <token>" header
4. Protected routes validate token and identify user

API Endpoints:
- POST /register     - Register new user (JSON)
- POST /login        - Login and get JWT token (JSON)
- GET  /api/protected - Get authenticated user info (protected)
- POST /users/       - Register new user (OAuth2 compatible)
- POST /token        - Login and get JWT token (OAuth2 form)
- GET  /users/me     - Get current user info (protected)
- GET  /tasks/       - List user's tasks (protected)
- POST /tasks/       - Create task for user (protected)
"""

from datetime import timedelta
from typing import List

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from database import engine, get_db, Base
import models
import schemas
from auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_active_user,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI application
app = FastAPI(
    title="Session 6: JWT Authentication API",
    description="Secure API with user authentication and protected routes",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# User Registration & Authentication
# =============================================================================

@app.post("/users/", response_model=schemas.User, status_code=201)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.

    The password is hashed before storage - we never store plain passwords.

    Args:
        user: Email and password for registration

    Returns:
        The created user (without password)

    Raises:
        400: If email is already registered
    """
    # Check if email already exists
    existing_user = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create user with hashed password
    db_user = models.User(
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/token", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT access token.

    Uses OAuth2 password flow - expects form data with:
    - username: The user's email
    - password: The user's password

    Returns:
        JWT token for authenticating future requests

    Raises:
        401: If credentials are invalid

    Note:
        OAuth2 uses 'username' field even though we use email as identifier.
        This is for compatibility with standard OAuth2 tools and libraries.
    """
    # Look up user by email (sent as 'username' in OAuth2 form)
    user = db.query(models.User).filter(
        models.User.email == form_data.username
    ).first()

    # Verify user exists and password is correct
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token with user's email as subject
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_active_user)):
    """
    Get current authenticated user's information.

    This is a protected endpoint - requires valid JWT token.
    The get_current_active_user dependency handles:
    - Extracting token from Authorization header
    - Validating the token
    - Looking up the user
    - Checking user is active

    Returns:
        Current user's profile
    """
    return current_user


# =============================================================================
# Convenience Endpoints (JSON-based, matching activity instructions)
# These wrap the same logic as the OAuth2 endpoints above but accept JSON
# =============================================================================

@app.post("/register", response_model=schemas.User, status_code=201)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user (JSON body). Delegates to create_user."""
    return create_user(user, db)


@app.post("/login", response_model=schemas.Token)
def login_json(
    credentials: schemas.LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Login with JSON body and return JWT token.

    Accepts {"email": "...", "password": "..."} instead of OAuth2 form data.
    """
    user = db.query(models.User).filter(
        models.User.email == credentials.email
    ).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/protected")
def protected_endpoint(
    current_user: models.User = Depends(get_current_active_user)
):
    """Protected endpoint requiring valid Bearer token."""
    return {"message": "Authenticated user", "email": current_user.email}


# =============================================================================
# Protected Task Endpoints
# Tasks are scoped to the authenticated user
# =============================================================================

@app.post("/tasks/", response_model=schemas.Task, status_code=201)
def create_task(
    task: schemas.TaskCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Create a new task for the authenticated user.

    The task is automatically associated with the current user
    via the owner_id foreign key.
    """
    db_task = models.Task(
        title=task.title,
        description=task.description,
        completed=False,
        owner_id=current_user.id  # Associate task with current user
    )

    db.add(db_task)
    db.commit()
    db.refresh(db_task)

    return db_task


@app.get("/tasks/", response_model=List[schemas.Task])
def list_tasks(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    """
    List all tasks for the authenticated user.

    Users can only see their own tasks - the query filters by owner_id.
    This is a fundamental security pattern for multi-user applications.
    """
    tasks = db.query(models.Task).filter(
        models.Task.owner_id == current_user.id
    ).all()

    return tasks


@app.get("/tasks/{task_id}", response_model=schemas.Task)
def get_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Get a specific task (if owned by current user).

    Note the double filter: by task_id AND owner_id.
    This prevents users from accessing other users' tasks.
    """
    task = db.query(models.Task).filter(
        models.Task.id == task_id,
        models.Task.owner_id == current_user.id
    ).first()

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    return task


@app.put("/tasks/{task_id}", response_model=schemas.Task)
def update_task(
    task_id: int,
    task_update: schemas.TaskUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Update a task (if owned by current user).
    """
    task = db.query(models.Task).filter(
        models.Task.id == task_id,
        models.Task.owner_id == current_user.id
    ).first()

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    update_data = task_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(task, field, value)

    db.commit()
    db.refresh(task)

    return task


@app.delete("/tasks/{task_id}", status_code=204)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Delete a task (if owned by current user).
    """
    task = db.query(models.Task).filter(
        models.Task.id == task_id,
        models.Task.owner_id == current_user.id
    ).first()

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    db.delete(task)
    db.commit()

    return None


# =============================================================================
# Utility Endpoints
# =============================================================================

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    user_count = db.query(models.User).count()
    task_count = db.query(models.Task).count()

    return {
        "status": "healthy",
        "database": "connected",
        "user_count": user_count,
        "task_count": task_count
    }
