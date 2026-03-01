FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/credential_monitor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/credential_monitor/credential_monitor.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 5004
CMD ["python", "credential_monitor.py"]
