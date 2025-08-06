FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY alert_sink_neo4j.py .
COPY ../../common /app/common
ENV PYTHONUNBUFFERED=1
CMD ["python","alert_sink_neo4j.py"]