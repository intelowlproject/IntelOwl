FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git

# Clone Phunter
RUN git clone https://github.com/N0rz3/Phunter.git /app/Phunter

# Set working directory
WORKDIR /app

# Copy requirements file and app.py to the working directory
COPY requirements.txt app.py ./

# Install Python packages
RUN --mount=type=cache,target=/root/.cache/uv uv pip install --system -r requirements.txt -r /app/Phunter/requirements.txt

# Expose port
EXPOSE 5612

# Run the app
CMD ["python", "app.py"]