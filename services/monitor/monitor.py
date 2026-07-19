from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
from datetime import datetime

class MonitorHandler(FileSystemEventHandler):

    def log(self, message):
        print(f"[{datetime.now()}] {message}")

    def on_created(self, event):
        if not event.is_directory:
            self.log(f"File Created: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self.log(f"File Modified: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            self.log(f"File Deleted: {event.src_path}")

if __name__ == "__main__":
    path = "test_folder"   # folder to monitor

    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    observer.start()
    print("Monitoring started...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()