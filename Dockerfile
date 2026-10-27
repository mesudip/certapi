FROM python:3.11.18-alpine3.24

# Set work directory
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV RENEW_QUEUE_SIZE=5

# Install system dependencies
# apk upgrade picks up Alpine fixes released after the base image was built
# postgresql-dev for psycopg2
# gcc, musl-dev for building python extensions (the base image already has the Python headers)
# libffi-dev, openssl-dev for cryptography
RUN apk upgrade --no-cache && apk add --no-cache \
    postgresql-dev \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev

# Install python dependencies
COPY requirements.txt .
# The base image ships the pip and setuptools bundled with Python 3.11, which are well behind upstream.
# Nothing runs pip at runtime, so pip, setuptools and wheel are removed once the dependencies are installed.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    python -m pip uninstall -y pip setuptools wheel


RUN addgroup -g 1261 certuser && \
    adduser -u 1261 -G certuser -D certuser && \
    mkdir -p /app/acme-challenges /app/db && \
    chown -R certuser:0 /app && \
    chmod -R g+w /app

# Copy application code
COPY ./src ./src
RUN chown -R certuser:0 /app/src && \
    chmod -R g+w /app/src

# Expose the application port (must be > 1024 for rootless)
EXPOSE 8080
VOLUME ["/app/db"]
VOLUME ["/app/acme-challenges"]


# Set HOME environment variable to a writable directory
ENV HOME=/app

# Set PYTHONPATH to include the src directory
ENV PYTHONPATH=/app/src

# Switch to the non-root user UID 1261
USER 1261

# Command to run the application using gunicorn
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "6", "--access-logfile", "-", "app:app"]