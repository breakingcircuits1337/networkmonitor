FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ids_alert_forwarder.py .
COPY ../../common /app/common
ENV PYTHONUNBUFFERED=1
CMD ["python", "ids_alert_forwarder.py"]