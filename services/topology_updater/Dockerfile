FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY topology_updater.py .
COPY ../../common /app/common
ENV PYTHONUNBUFFERED=1
CMD ["python", "topology_updater.py"]