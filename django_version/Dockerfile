# Base image — official Python
FROM python:3.14.6-slim

# Install uv from its official image, pinned
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /bin/

# Prevents Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1

# Prevents Python from buffering stdout/stderr (logs appear immediately)
ENV PYTHONUNBUFFERED=1

# Build the project environment outside /app, which docker-compose bind-mounts
ENV UV_PROJECT_ENVIRONMENT=/opt/venv

# Use the interpreter the base image ships; never download another one
ENV UV_PYTHON_DOWNLOADS=never

# Put the project environment first on PATH
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better Docker cache usage)
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked

# Copy project files into the container
COPY . .

# Expose the port Django will run on
EXPOSE 8000

# Start the development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
