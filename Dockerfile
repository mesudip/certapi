FROM python:3.11-alpine

# Set work directory
WORKDIR /app

# Install system dependencies
# postgresql-dev for psycopg2
# gcc, musl-dev, python3-dev for building python extensions
# libffi-dev, openssl-dev for cryptography
RUN apk add --no-cache \
    postgresql-dev \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir flask flask-restx psycopg2

# Copy application code
COPY ./src ./src

# Expose the application port
EXPOSE 8081
VOLUME ["/app/db"]
# Command to run the application
ENTRYPOINT ["python", "src/app.py"]
