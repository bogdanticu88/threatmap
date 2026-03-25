FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install threatmap package
RUN pip install --no-cache-dir -e .

# Expose API port
EXPOSE 8000

# Default to API mode
ENTRYPOINT ["threatmap", "serve"]
CMD ["--host", "0.0.0.0"]
