#!/usr/bin/env python3
import subprocess
import time
import datetime
import signal
import sys

def main():
    # Start caffeinate in background
    process = subprocess.Popen(["caffeinate", "-dimsu"])
    start_time = time.time()
    print(f"Started caffeinate (PID: {process.pid}) at {datetime.datetime.now()}")

    try:
        while True:
            time.sleep(300)  # 300 seconds = 5 minutes
            elapsed = int(time.time() - start_time)

            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)

            print(f"[{datetime.datetime.now()}] "
                  f"Caffeinate has been running for {hours}h {minutes}m {seconds}s")

    except KeyboardInterrupt:
        print("\nStopping script (Ctrl-C pressed)...")
    finally:
        # Make sure caffeinate is killed
        process.terminate()
        process.wait()
        print(f"Caffeinate stopped at {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
