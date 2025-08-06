FROM python:3.11-slim
RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY packet_launcher.py .
COPY ../../common /app/common
ENV PYTHONUNBUFFERED=1
CMD ["python", "packet_launcher.py"]