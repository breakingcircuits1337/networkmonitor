FROM python:3.11-slim

WORKDIR /app
COPY services/ai_analyst/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/ai_analyst/ai_analyst.py .
COPY common /app/common

ENV PYTHONUNBUFFERED=1
ENV KAFKA_BOOTSTRAP=kafka:9092
ENV OLLAMA_URL=http://ollama:11434
ENV NEO4J_URI=bolt://neo4j:7687
ENV NEO4J_USER=neo4j
ENV ANALYSIS_TOPICS=alert.correlated,security.alerts,dpi.events,voip.events
ENV BATCH_WINDOW_SECONDS=30
ENV IMMEDIATE_SEVERITY=2
ENV MAX_BATCH_SIZE=20
ENV HTTP_PORT=5001
ENV SUMMARY_INTERVAL_MINUTES=60

EXPOSE 5001

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "ai_analyst.py"]
