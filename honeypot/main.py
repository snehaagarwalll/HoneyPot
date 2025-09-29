import threading
import signal
import sys
from honeypot.services.http_service import run_http_server
from honeypot.services.ssh_service import run_ssh_like
from honeypot.services.ftp_service import run_ftp_server

def main():
    threads = []
    t_http = threading.Thread(target=run_http_server, kwargs={}, daemon=True)
    t_ssh  = threading.Thread(target=run_ssh_like, kwargs={}, daemon=True)
    t_ftp  = threading.Thread(target=run_ftp_server, kwargs={}, daemon=True)
    threads.extend([t_http, t_ssh, t_ftp])

    for t in threads:
        t.start()

    print("[*] Honeypot running. Press Ctrl+C to stop.")
    def _stop(sig, frame):
        print("[*] Shutting down honeypot.")
        # services are daemon threads; exiting process suffices
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    
    # Windows-compatible way to keep the main thread alive
    try:
        if hasattr(signal, 'pause'):
            signal.pause()
        else:
            # Windows doesn't have signal.pause(), use input() to block
            while True:
                try:
                    import time
                    time.sleep(1)
                except KeyboardInterrupt:
                    break
    except KeyboardInterrupt:
        print("[*] Shutting down honeypot.")
        sys.exit(0)

if __name__ == "__main__":
    main()
