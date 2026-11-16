# Session 6: JWT Authentication API Dockerfile
#
# This Dockerfile creates a containerized FastAPI application.
# Used with docker-compose.yml for the complete development environment.
# Session 6 uses SQLite (no PostgreSQL dependencies needed).

# Use official Python image (slim variant for smaller size)
FROM python:3.12-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements first (Docker layer caching optimization)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the FastAPI port
EXPOSE 8000

# Default command (can be overridden in docker-compose.yml)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
