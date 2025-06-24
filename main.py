from scanner import VulnerabilityScanner
from report import ReportGenerator
from logger import ScanLogger

def main():
    print("Welcome to the Web Vulnerability Scanner!")
    url = input("Enter the website URL to scan (e.g., http://example.com): ").strip()
    
    # Ensure URL starts with http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print(f"\nScanning {url}... (This may take a moment due to parallel scanning)\n")
    
    # Run the scanner
    scanner = VulnerabilityScanner(url)
    results = scanner.scan()
    
    # Generate and display the report
    reporter = ReportGenerator(results)
    reporter.generate()
    
    # Log results to file
    logger = ScanLogger()
    logger.log_results(url, results)
    print(f"Results saved to scan_log.txt")

if __name__ == "__main__":
    main()