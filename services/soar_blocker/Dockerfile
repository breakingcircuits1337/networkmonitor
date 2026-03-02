FROM python:3.11-slim
WORKDIR /app
COPY services/soar_blocker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/soar_blocker/soar_blocker.py .
COPY common /app/common
ENV PYTHONUNBUFFERED=1
ENV OLLAMA_URL=http://ollama:11434
ENV LLM_BLOCK_ENABLED=false
ENV LLM_BLOCK_CONFIDENCE=0.8
ENV LLM_FALLBACK_BLOCK=true
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "soar_blocker.py"]