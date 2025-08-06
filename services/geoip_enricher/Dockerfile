FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY geoip_enricher.py .
COPY ../../common /app/common
# Expect GeoLite2-City.mmdb to be mounted at /geoip/GeoLite2-City.mmdb
ENV GEOIP_DB="/geoip/GeoLite2-City.mmdb" \
    PYTHONUNBUFFERED=1
CMD ["python","geoip_enricher.py"]