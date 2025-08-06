FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY soar_blocker.py .
COPY ../../common /app/common
ENV PYTHONUNBUFFERED=1
CMD ["python", "soar_blocker.py"]