FROM python:3.12-slim

# Environment variables
ENV PROJECT_PATH=/opt/deploy/bbot
ENV HOME=${PROJECT_PATH}
ENV BBOT_HOME=${PROJECT_PATH}

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libffi-dev && \
    apt-get clean && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/*

# Set up project directory
WORKDIR ${PROJECT_PATH}

# Copy application files and requirements
COPY requirements.txt app.py ./

# Upgrade pip and install Python packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Pre-install BBOT dependencies
RUN bbot --install-all-deps -y --force

# Make script executable
RUN chmod u+x app.py

# Expose port
EXPOSE 5001

# Entrypoint
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001", "--log-level", "debug"]
