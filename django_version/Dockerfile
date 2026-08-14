# Base image — official Python
FROM python:3.14.6-slim

# Prevents Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1

# Prevents Python from buffering stdout/stderr (logs appear immediately)
ENV PYTHONUNBUFFERED=1

# Set working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better Docker cache usage)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy project files into the container
COPY . .

# Expose the port Django will run on
EXPOSE 8000

# Start the development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
