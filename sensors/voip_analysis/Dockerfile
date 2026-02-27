FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pyshark kafka-python-ng python-dotenv

WORKDIR /app
COPY sensors/voip_analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/voip_analysis/voip_sensor.py .
COPY common /app/common

ENV INTERFACE=eth0
ENV KAFKA_BOOTSTRAP=kafka:9092
ENV KAFKA_TOPIC=voip.events

CMD ["python", "voip_sensor.py"]
