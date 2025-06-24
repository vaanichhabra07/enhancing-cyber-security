from colorama import init, Fore, Style

class ReportGenerator:
    def __init__(self, results):
        self.results = results
        init()  # Initialize colorama for colored output

    def generate(self):
        print(f"\n{Style.BRIGHT}=== Vulnerability Scan Report ==={Style.RESET_ALL}")
        for vuln, status in self.results.items():
            if status == 'Vulnerable' or 'Missing headers' in status:
                print(f"{Fore.RED}[VULNERABLE] {vuln}: {status}{Style.RESET_ALL}")
            elif status == 'Safe':
                print(f"{Fore.GREEN}[SAFE] {vuln}: No issues detected.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[ERROR] {vuln}: {status}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}================================{Style.RESET_ALL}\n")