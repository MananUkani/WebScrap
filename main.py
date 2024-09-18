import os
import requests
import ssl
import socket
import logging
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from jinja2 import Template
import re
import nmap
from requests.exceptions import RequestException

# Define vulnerability weights
VULNERABILITY_WEIGHTS = {
    'SSL Certificate': 10,
    'Firewall': 10,
    'Open Directory': 5,
    'Sensitive File': 7,
    'HTTP Method': 4,
    'Clickjacking Protection Missing': 6,
    'Content Security Policy Missing': 8,
    'Missing Security Headers': 9
}

def configure_logging(url):
    """Configure logging to a file."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    sanitized_url = sanitize_filename(url.split('//')[-1].replace('/', '_'))
    log_filename = f"{sanitized_url}-{timestamp}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')
    return log_filename

def sanitize_filename(filename):
    """Sanitize filenames to avoid invalid characters."""
    return re.sub(r'[<>:"/\\|?*]', '', filename)

def fetch_and_parse(url):
    """Fetch and parse the HTML content from a URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup
    except RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return None

def get_all_links(soup, base_url):
    """Extract all links from the HTML content."""
    links = set()
    for tag in soup.find_all(['a', 'img', 'link', 'script']):
        href = tag.get('href') or tag.get('src')
        if href:
            full_url = urljoin(base_url, href)
            links.add(full_url)
    return links

def check_ssl_certificate(url, results):
    """Check the SSL certificate of the given URL."""
    try:
        hostname = url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    results.append(('SSL Certificate', url))
                    logging.info(f"Valid SSL Certificate: {url}")
    except Exception as e:
        logging.error(f"Error checking SSL certificate for {url}: {e}")

def check_firewall(url, results):
    """Check if a firewall is blocking the URL."""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=url, arguments='-Pn')
        if 'filtered' in nm[url].state():
            results.append(('Firewall', url))
            logging.info(f"Firewall detected: {url}")
    except Exception as e:
        logging.error(f"Error checking firewall for {url}: {e}")

def scan_directories(base_url, results, user_agent):
    """Scan for open directories."""
    DIRECTORY_LIST = ['admin/', 'login/', 'dashboard/', 'uploads/', 'files/']
    for directory in DIRECTORY_LIST:
        test_url = urljoin(base_url, directory)
        check_url(test_url, 'Open Directory', results, user_agent)

def scan_sensitive_files(base_url, results, user_agent):
    """Scan for sensitive files."""
    FILE_LIST = ['index.php', 'admin.php', 'config.php', 'login.php', '.env']
    for file in FILE_LIST:
        test_url = urljoin(base_url, file)
        check_url(test_url, 'Sensitive File', results, user_agent)

def check_http_methods(url, methods, results, user_agent):
    """Test allowed HTTP methods."""
    headers = {'User-Agent': user_agent}
    for method in methods:
        try:
            response = requests.request(method, url, headers=headers, timeout=5)
            if response.status_code in [200, 204, 405]:
                results.append((f"{method} allowed", url))
                logging.info(f"{method} allowed: {url}")
        except RequestException as e:
            logging.error(f"Error testing {url} with {method}: {e}")

def check_url(url, vulnerability_type, results, user_agent):
    """Check a URL for a specific vulnerability."""
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code in [200, 403, 404]:
            results.append((f"{vulnerability_type} - Status Code: {response.status_code}", url))
            logging.info(f"Found {vulnerability_type}: {url}")
    except RequestException as e:
        logging.error(f"Error checking {url} for {vulnerability_type}: {e}")

def check_clickjacking_protection(url, results, user_agent):
    """Check if the website has protection against clickjacking."""
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if 'X-Frame-Options' not in response.headers:
            results.append(('Clickjacking Protection Missing', url))
            logging.info(f"Clickjacking protection missing: {url}")
    except RequestException as e:
        logging.error(f"Error checking clickjacking protection for {url}: {e}")

def check_content_security_policy(url, results, user_agent):
    """Check if the website has a Content Security Policy (CSP)."""
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if 'Content-Security-Policy' not in response.headers:
            results.append(('Content Security Policy Missing', url))
            logging.info(f"Content Security Policy missing: {url}")
    except RequestException as e:
        logging.error(f"Error checking Content Security Policy for {url}: {e}")

def check_security_headers(url, results, user_agent):
    """Check for important security headers."""
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        missing_headers = []
        if 'Strict-Transport-Security' not in response.headers:
            missing_headers.append('Strict-Transport-Security')
        if 'X-Content-Type-Options' not in response.headers:
            missing_headers.append('X-Content-Type-Options')
        if 'X-XSS-Protection' not in response.headers:
            missing_headers.append('X-XSS-Protection')
        if missing_headers:
            results.append((f"Missing Security Headers: {', '.join(missing_headers)}", url))
            logging.info(f"Missing security headers: {url} - {', '.join(missing_headers)}")
    except RequestException as e:
        logging.error(f"Error checking security headers for {url}: {e}")

def calculate_security_score(results):
    """Calculate the security score based on found vulnerabilities."""
    total_weight = sum(VULNERABILITY_WEIGHTS.values())
    found_weight = sum(VULNERABILITY_WEIGHTS.get(vuln, 0) for vuln, _ in results)
    logging.info(f"Total Weight: {total_weight}, Found Weight: {found_weight}")
    security_score = 100 - (found_weight / total_weight * 100)
    return max(security_score, 0)

def generate_html_report(results, security_score, file_name='report.html'):
    """Generate an HTML report of the scan results."""
    template = Template("""<html>
    <head><title>Scan Report</title></head>
    <body>
    <h1>Scan Report</h1>
    <p>Security Score: {{ security_score }}%</p>
    <ul>
    {% for vuln, url in results %}
        <li>{{ vuln }}: {{ url }}</li>
    {% endfor %}
    </ul>
    </body>
    </html>""")
    with open(file_name, 'w') as file:
        file.write(template.render(results=results, security_score=security_score))

def main():
    base_url = input("Enter the URL to scan (including http/https): ")
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    sanitized_url = sanitize_filename(base_url.split('//')[-1].replace('/', '_'))
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_filename = configure_logging(base_url)
    
    print("Fetching resources...")
    visited_urls = set()
    urls_to_visit = [base_url]
    resource_urls = set()

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_and_parse, url): url for url in urls_to_visit}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                soup = future.result()
                if soup:
                    links = get_all_links(soup, base_url)
                    urls_to_visit.extend(links)
                    resource_urls.update(links)
            except Exception as e:
                logging.error(f"Error processing {url}: {e}")

    results = []

    print("Scanning for vulnerabilities...")
    check_ssl_certificate(base_url, results)
    check_firewall(base_url, results)   
    scan_directories(base_url, results, user_agent)
    scan_sensitive_files(base_url, results, user_agent)
    check_clickjacking_protection(base_url, results, user_agent)
    check_content_security_policy(base_url, results, user_agent)
    check_security_headers(base_url, results, user_agent)

    http_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    for url in urls_to_visit:
        check_http_methods(url, http_methods, results, user_agent)

    security_score = calculate_security_score(results)
    generate_html_report(results, security_score)

    print(f"Scan complete. Security score: {security_score}%")
    print(f"Scan results saved in {log_filename}")

if __name__ == "__main__":
    main()
