FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt PyYAML

COPY . .

EXPOSE 8000

CMD ["python", "run_scanner.py", "--web", "--host", "0.0.0.0", "--port", "8000"]
