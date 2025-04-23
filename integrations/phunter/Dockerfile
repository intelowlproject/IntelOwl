FROM python:3.12-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git

# Clone Phunter
RUN git clone https://github.com/N0rz3/Phunter.git /app/Phunter

# Set working directory
WORKDIR /app

# Copy requirements file and app.py to the working directory
COPY requirements.txt app.py ./

# Upgrade pip and install Python packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r /app/Phunter/requirements.txt

# Expose port
EXPOSE 5000

# Run the app
CMD ["python", "app.py"]