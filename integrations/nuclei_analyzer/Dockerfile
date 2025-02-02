# Use the official Nuclei image as the base
FROM projectdiscovery/nuclei:v3.3.8

ENV LOG_PATH=/var/log/nuclei_analyzer
ENV USER=nuclei-user

# Install required packages using apk (Alpine Package Keeper)
RUN apk add --no-cache python3 py3-pip

# Create a working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the Flask API code
COPY app.py .

# Expose the API port
EXPOSE 5000

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# RUN nuclei -update-template-dir /opt/nuclei-api/nuclei-templates -update-templates

ENTRYPOINT ["/entrypoint.sh"]
