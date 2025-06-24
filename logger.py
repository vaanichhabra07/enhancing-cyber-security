from datetime import datetime

class ScanLogger:
    def __init__(self, log_file="scan_log.txt"):
        self.log_file = log_file

    def log_results(self, url, results):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] Scan for {url}\n")
            for vuln, status in results.items():
                f.write(f"  {vuln}: {status}\n")
            f.write("-" * 50 + "\n")