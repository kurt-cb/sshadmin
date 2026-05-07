FROM python:3.11-slim

WORKDIR /app

# Install OpenSSH for ssh-keygen
RUN apt-get update && apt-get install -y openssh-client && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sshadmin.py ssh_auth_server.py ./
COPY templates/ templates/

# Create necessary directories
RUN mkdir -p /app/instance

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/').read()"

# Run the application
CMD ["python3", "sshadmin.py"]
