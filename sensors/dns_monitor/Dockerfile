FROM python:3.11-slim
RUN apt-get update && apt-get install -y libpcap-dev libnet1-dev curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY sensors/dns_monitor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/dns_monitor/dns_monitor.py .
ENV PYTHONUNBUFFERED=1 \
    INTERFACE=eth0 \
    DGA_ENTROPY_THRESH=3.6 \
    ENABLE_EPHEMERAL_TRACER=false
RUN useradd -m -u 1000 appuser
USER appuser
EXPOSE 5005
CMD ["python", "dns_monitor.py"]
