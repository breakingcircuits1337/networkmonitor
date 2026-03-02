FROM python:3.11-slim
WORKDIR /app
COPY sensors/dpi_event_forwarder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/dpi_event_forwarder/dpi_event_forwarder.py .
COPY common /app/common
ENV PYTHONUNBUFFERED=1

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "dpi_event_forwarder.py"]