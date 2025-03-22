FROM python:3.12-slim

# Environment variables
ENV PROJECT_PATH=/opt/deploy/bbot
ENV USER=bbot-user
ENV HOME=${PROJECT_PATH}
ENV BBOT_HOME=${PROJECT_PATH}

# Create a non-root user
RUN useradd -ms /bin/bash ${USER}

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    debianutils build-essential libssl-dev libffi-dev cargo openssl \
    libpq-dev curl unzip git make bash tar p7zip-full p7zip && \
    apt-get clean && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/*


# Upgrade pip and install Python packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir fastapi uvicorn[standard] bbot

# Pre-install BBOT dependencies
RUN bbot --install-all-deps -y --force

# Set up project directory
WORKDIR ${PROJECT_PATH}

# Copy application files
COPY --chown=${USER}:${USER} app.py ./

# Make scripts executable
RUN chmod u+x app.py

# Expose port
EXPOSE 5001

# Entrypoint
# ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001", "--log-level", "debug"]