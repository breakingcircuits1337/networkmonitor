FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/geoip_enricher/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/geoip_enricher/geoip_enricher.py .
COPY common /app/common
# Expect GeoLite2-City.mmdb to be mounted at /geoip/GeoLite2-City.mmdb
ENV GEOIP_DB="/geoip/GeoLite2-City.mmdb" \
    PYTHONUNBUFFERED=1
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python","geoip_enricher.py"]