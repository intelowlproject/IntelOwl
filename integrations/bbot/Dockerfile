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

ENV BBOT_DISABLE_DEPSINSTALL=1  
ENV BBOT_SKIP_FIRST_RUN=1 


# Set up project directory
WORKDIR ${PROJECT_PATH}

# Copy application files
COPY --chown=${USER}:${USER} app.py entrypoint.sh ./

# Make scripts executable
RUN chmod u+x entrypoint.sh app.py

# Expose port
EXPOSE 5000

# Entrypoint
ENTRYPOINT ["./entrypoint.sh"]