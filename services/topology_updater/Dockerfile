FROM python:3.11-slim
WORKDIR /app
COPY services/topology_updater/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/topology_updater/topology_updater.py .
COPY common /app/common
ENV PYTHONUNBUFFERED=1
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "topology_updater.py"]