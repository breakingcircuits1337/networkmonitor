FROM python:3.11-slim
WORKDIR /app
COPY sensors/ids_alert_forwarder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/ids_alert_forwarder/ids_alert_forwarder.py .
COPY common /app/common
ENV PYTHONUNBUFFERED=1

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "ids_alert_forwarder.py"]