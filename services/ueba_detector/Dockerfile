FROM python:3.11-slim
WORKDIR /app
COPY services/ueba_detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/ueba_detector/ueba_detector.py .
COPY common /app/common
ENV PYTHONUNBUFFERED=1

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "ueba_detector.py"]
