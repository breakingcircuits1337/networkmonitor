FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir kafka-python-ng

WORKDIR /app
COPY sensors/tshark_capture/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/tshark_capture/tshark_capture.py .
COPY common /app/common

ENV INTERFACE=eth0
ENV CAPTURE_DIR=/captures
ENV KAFKA_BOOTSTRAP=kafka:9092
ENV KAFKA_TOPIC=voip.packets
ENV ROTATION_SECONDS=300

ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "tshark_capture.py"]
