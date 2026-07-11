FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 deception && \
    chown -R deception:deception /app
USER deception

# Expose ports
# 2222 - SSH Honeypot
# 8080 - HTTP Honeypot
# 3306 - Database Honeypot
# 445 - SMB Honeypot
# 5000 - Dashboard
EXPOSE 2222 8080 3306 445 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/health')" || exit 1

# Run the application
CMD ["python", "main.py", "--config", "config.yaml"]
