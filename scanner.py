import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import json
import threading
from queue import Queue

class VulnerabilityScanner:
    def __init__(self, url, config_file="config.json"):
        self.url = url
        self.session = requests.Session()
        self.results = {}
        self.queue = Queue()
        self.lock = threading.Lock()
        # Load payloads from config file
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            self.sql_payloads = config.get('sql_injection_payloads', ["'", "1' OR '1'='1"])
            self.xss_payloads = config.get('xss_payloads', ["<script>alert('xss')</script>"])
        except Exception as e:
            print(f"Error loading config: {e}")
            self.sql_payloads = ["'", "1' OR '1'='1"]
            self.xss_payloads = ["<script>alert('xss')</script>"]

    def test_sql_injection(self):
        """Test for SQL Injection with multiple payloads and false positive checks."""
        vulnerable = False
        error_patterns = [r"sql syntax", r"mysql", r"database error", r"sqlite"]
        try:
            response = self.session.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                if action:
                    form_url = urljoin(self.url, action)
                    inputs = form.find_all('input')
                    data = {input.get('name'): 'test' for input in inputs if input.get('name')}
                    positive_count = 0
                    for payload in self.sql_payloads:
                        for key in data:
                            temp_data = data.copy()
                            temp_data[key] = payload
                            res = self.session.post(form_url, data=temp_data, timeout=5)
                            if any(re.search(pattern, res.text.lower()) for pattern in error_patterns):
                                positive_count += 1
                        # Require at least 2 positive results to reduce false positives
                        if positive_count >= 2:
                            vulnerable = True
                            break
                    if vulnerable:
                        break
            self.results['SQL Injection'] = 'Vulnerable' if vulnerable else 'Safe'
        except Exception as e:
            self.results['SQL Injection'] = f"Error: {str(e)}"

    def test_xss(self):
        """Test for XSS with payloads from config and false positive checks."""
        vulnerable = False
        try:
            response = self.session.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                if action:
                    form_url = urljoin(self.url, action)
                    inputs = form.find_all('input')
                    data = {input.get('name'): '' for input in inputs if input.get('name')}
                    positive_count = 0
                    for payload in self.xss_payloads:
                        for key in data:
                            temp_data = data.copy()
                            temp_data[key] = payload
                            res = self.session.post(form_url, data=temp_data, timeout=5)
                            # Check if payload appears unescaped in response
                            if payload in res.text and 'htmlspecialchars' not in res.text.lower():
                                positive_count += 1
                        # Require at least 2 positive results
                        if positive_count >= 2:
                            vulnerable = True
                            break
                    if vulnerable:
                        break
            self.results['XSS'] = 'Vulnerable' if vulnerable else 'Safe'
        except Exception as e:
            self.results['XSS'] = f"Error: {str(e)}"

    def test_directory_listing(self):
        """Check if directory listing is enabled with enhanced checks."""
        directories = ['/admin/', '/uploads/', '/files/', '/backup/', '/config/', '/data/']
        vulnerable = False
        try:
            for dir in directories:
                test_url = urljoin(self.url, dir)
                response = self.session.get(test_url, timeout=5)
                # Check for "Index of" and HTML patterns indicating a directory listing
                if (response.status_code == 200 and 
                    "Index of" in response.text and 
                    re.search(r'<a href="[^"]+">', response.text)):
                    vulnerable = True
                    break
            self.results['Directory Listing'] = 'Vulnerable' if vulnerable else 'Safe'
        except Exception as e:
            self.results['Directory Listing'] = f"Error: {str(e)}"

    def test_clickjacking(self):
        """Check for Clickjacking via X-Frame-Options and CSP headers."""
        vulnerable = True
        try:
            response = self.session.get(self.url, timeout=5)
            headers = response.headers
            # Check X-Frame-Options
            if 'X-Frame-Options' in headers:
                vulnerable = False
            # Check Content-Security-Policy for frame-ancestors
            elif 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy'].lower()
                if 'frame-ancestors' in csp:
                    vulnerable = False
            self.results['Clickjacking'] = 'Vulnerable' if vulnerable else 'Safe'
        except Exception as e:
            self.results['Clickjacking'] = f"Error: {str(e)}"

    def test_csrf(self):
        """Check for CSRF by looking for missing CSRF tokens in forms."""
        vulnerable = False
        try:
            response = self.session.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            if not forms:
                self.results['CSRF'] = 'Safe (No forms found)'
                return
            vulnerable_forms = 0
            for form in forms:
                if form.get('method', '').lower() == 'post':
                    inputs = form.find_all('input', {'type': 'hidden'})
                    has_token = False
                    for input in inputs:
                        name = input.get('name', '').lower()
                        value = input.get('value', '')
                        # Look for common CSRF token names or long random values
                        if (name in ['csrf_token', 'csrftoken', 'authenticity_token', '_token'] or
                            (len(value) > 20 and re.match(r'^[a-zA-Z0-9\-_]+$', value))):
                            has_token = True
                            break
                    if not has_token:
                        vulnerable_forms += 1
            # Require at least 2 vulnerable forms to reduce false positives
            if vulnerable_forms >= 2 or (len(forms) == vulnerable_forms and vulnerable_forms > 0):
                vulnerable = True
            self.results['CSRF'] = 'Vulnerable' if vulnerable else 'Safe'
        except Exception as e:
            self.results['CSRF'] = f"Error: {str(e)}"

    def test_security_headers(self):
        """Check for missing security headers."""
        required_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options'
        ]
        missing_headers = []
        try:
            response = self.session.get(self.url, timeout=5)
            headers = response.headers
            for header in required_headers:
                if header not in headers:
                    missing_headers.append(header)
            if missing_headers:
                self.results['Security Headers'] = f"Missing headers: {', '.join(missing_headers)}"
            else:
                self.results['Security Headers'] = 'Safe'
        except Exception as e:
            self.results['Security Headers'] = f"Error: {str(e)}"

    def worker(self):
        """Worker function for multithreading."""
        while not self.queue.empty():
            test_func = self.queue.get()
            with self.lock:
                test_func()
            self.queue.task_done()

    def scan(self):
        """Run all vulnerability tests in parallel."""
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_directory_listing,
            self.test_clickjacking,
            self.test_csrf,
            self.test_security_headers
        ]
        # Add tests to queue
        for test in tests:
            self.queue.put(test)
        # Start threads
        threads = []
        for _ in range(min(len(tests), 5)):  # Max 5 threads
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        # Wait for all threads to finish
        for t in threads:
            t.join()
        return self.results