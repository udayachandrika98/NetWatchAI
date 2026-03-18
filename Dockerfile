FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for scapy (packet capture)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        tcpdump \
        iproute2 \
        net-tools \
        iputils-ping \
        curl \
        wireless-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Train the model during build so it's ready to use
RUN python train.py

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run the dashboard by default
CMD ["streamlit", "run", "dashboard.py", "--server.address", "0.0.0.0", "--server.port", "8501", "--browser.gatherUsageStats", "false"]
