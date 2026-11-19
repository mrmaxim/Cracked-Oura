"""Console stage timing and heartbeats; never prints auth bytes."""
import threading
import time


class Progress:
    def __init__(self, interval=3, output=print):
        self.started = time.monotonic()
        self.interval = interval
        self.output = output
        self.message = None
        self.stage_started = self.started
        self.last_output = self.started
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def _emit(self, text):
        now = time.monotonic()
        elapsed = int(now - self.started)
        self.output(f'[{elapsed // 60:02d}:{elapsed % 60:02d}] {text}', flush=True)
        self.last_output = now

    def set(self, message):
        with self.lock:
            self.message = message
            self.stage_started = time.monotonic()
            self._emit(message)

    def update(self, message):
        with self.lock:
            self.message = message
            self._emit(message)

    def _heartbeat(self):
        while not self.stop.wait(min(.2, self.interval)):
            with self.lock:
                if self.message and time.monotonic() - self.last_output >= self.interval:
                    waited = int(time.monotonic() - self.stage_started)
                    self._emit(f'{self.message} (этап: {waited} с)')

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=2)
