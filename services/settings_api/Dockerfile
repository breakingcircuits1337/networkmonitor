FROM python:3.11-slim
WORKDIR /app
COPY services/settings_api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/settings_api/settings_api.py .
RUN mkdir -p /data
ENV PYTHONUNBUFFERED=1 \
    SETTINGS_FILE=/data/settings.enc
EXPOSE 5002
RUN useradd -m -u 1000 appuser && chown appuser /data
USER appuser

CMD ["python", "settings_api.py"]
