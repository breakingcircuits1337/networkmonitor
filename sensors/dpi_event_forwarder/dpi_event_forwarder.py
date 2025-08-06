import os
import signal
import time
import json
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kafka import KafkaProducer

from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("dpi_event_forwarder")

class LogFileTailer:
    def __init__(self, kafka_producer, topic):
        self.offsets = {}  # path -> offset
        self.kafka_producer = kafka_producer
        self.topic = topic
        self.msg_count = 0

    def process(self, path):
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r") as f:
                # Seek to last offset (or end if new)
                seek_offset = self.offsets.get(path, None)
                if seek_offset is None:
                    f.seek(0, os.SEEK_END)
                    seek_offset = f.tell()
                else:
                    f.seek(seek_offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        self.kafka_producer.send(self.topic, record)
                        self.msg_count += 1
                        if self.msg_count % 200 == 0:
                            logger.info(f"Forwarded {self.msg_count} DPI records to Kafka")
                    except Exception as e:
                        logger.warning(f"Failed to parse Zeek log line: {e}")
                # Remember offset
                self.offsets[path] = f.tell()
        except Exception as e:
            logger.warning(f"Error reading {path}: {e}")

class ZeekLogHandler(FileSystemEventHandler):
    def __init__(self, tailer, log_dir):
        super().__init__()
        self.tailer = tailer
        self.log_dir = log_dir

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".log"):
            logger.info(f"Detected new Zeek log file: {event.src_path}")
            self.tailer.process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(".log"):
            self.tailer.process(event.src_path)

def initial_scan(log_dir, tailer):
    # On startup, process all existing .log files in current log dir
    if not os.path.exists(log_dir):
        logger.warning(f"Log dir {log_dir} does not exist yet.")
        return
    for fname in os.listdir(log_dir):
        if fname.endswith(".log"):
            path = os.path.join(log_dir, fname)
            tailer.process(path)

def main():
    log_dir = get_env("LOG_DIR", "/usr/local/zeek/logs/current")
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "dpi.events")
    logger.info(f"Starting DPI Event Forwarder")
    logger.info(f"Config: LOG_DIR={log_dir} KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic}")

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )

    tailer = LogFileTailer(producer, kafka_topic)
    observer = Observer()
    handler = ZeekLogHandler(tailer, log_dir)
    observer.schedule(handler, log_dir, recursive=False)

    stop_flag = {"stop": False}
    def handle_sigterm(sig, frame):
        logger.info("Received SIGTERM, shutting down gracefully...")
        stop_flag["stop"] = True
        observer.stop()

    signal.signal(signal.SIGTERM, handle_sigterm)

    # Initial scan (may not exist yet if Zeek not started)
    for _ in range(20):
        if os.path.exists(log_dir):
            initial_scan(log_dir, tailer)
            break
        else:
            logger.info(f"Waiting for Zeek log dir {log_dir} ...")
            time.sleep(3)
    else:
        logger.warning(f"Log dir {log_dir} not found after waiting, continuing anyway.")

    observer.start()
    try:
        while not stop_flag["stop"]:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down...")
        observer.stop()
    observer.join()
    logger.info("DPI Event Forwarder stopped.")

if __name__ == "__main__":
    main()