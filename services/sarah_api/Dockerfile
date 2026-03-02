FROM python:3.11-slim

RUN pip install --no-cache-dir --break-system-packages flask kafka-python-ng requests

WORKDIR /app
COPY services/sarah_api/requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt
COPY services/sarah_api/sarah_api.py .

ENV KAFKA_BOOTSTRAP=kafka:9092
ENV OLLAMA_URL=http://ollama:11434
ENV AI_ANALYST_URL=http://ai_analyst:5001

EXPOSE 5000

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "sarah_api.py"]
