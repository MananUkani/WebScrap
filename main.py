import os
import requests
from urllib.parse import urljoin
import logging
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Template
import re
from requests.exceptions import RequestException

def configure_logging(url):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_filename = f"{url.split('//')[-1].replace('/', '_')}-{timestamp}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')
    return log_filename

def sanitize_filename(filename):
    return re.sub(r'[<>:"/\\|?*]', '', filename)

def fetch_and_parse(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup
    except RequestException as e:
        logging.error(f"Error fetching {url}: {e}")

def get_all_links(soup, base_url):
    links = set()
    for tag in soup.find_all(['a', 'img', 'link', 'script']):
        href = tag.get('href') or tag.get('src')
        if href:
            full_url = urljoin(base_url, href)
            links.add(full_url)
    return links

def download_file(url, folder):
    local_filename = sanitize_filename(url.split('/')[-1]) or 'index.html'
    local_filepath = os.path.join(folder, local_filename)
    
    os.makedirs(folder, exist_ok=True)

    try:
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(local_filepath, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            logging.info(f"Downloaded: {url}")
        else:
            logging.info(f"Failed to download: {url} (Status code: {response.status_code})")
    except RequestException as e:
        logging.error(f"Error downloading {url}: {e}")

def scan_directories(base_url, results, user_agent):
    DIRECTORY_LIST = ['admin/', 'login/', 'dashboard/', 'uploads/', 'files/', 'admin/login/', 'admin/dashboard/', 'user/', 'admin/user/',
                      'backup/', 'config/', 'data/', 'includes/', 'scripts/', 'temp/', 'test/', 'cgi-bin/', 'webadmin/']
    for directory in DIRECTORY_LIST:
        test_url = urljoin(base_url, directory)
        check_url(test_url, results, user_agent)

def scan_files(base_url, results, user_agent):
    FILE_LIST = ['index.php', 'admin.php', 'config.php', 'login.php', 'dashboard.php', 'uploads.php', 'backup.php', 'data.php',
                 'settings.php', 'config.json', 'config.xml', 'config.yml', 'database.yml', '.env']
    for file in FILE_LIST:
        test_url = urljoin(base_url, file)
        check_url(test_url, results, user_agent)

def scan_sensitive_files(base_url, results, user_agent):
    SENSITIVE_FILES = ['.env', 'config.json', 'settings.xml', 'database.yml', 'admin/config.php', 'admin/.env']
    for file in SENSITIVE_FILES:
        test_url = urljoin(base_url, file)
        check_url(test_url, results, user_agent)

def check_url(url, results, user_agent):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            results.append(f"Found: {url}")
            logging.info(f"Found: {url}")
        elif response.status_code == 403:
            results.append(f"Forbidden: {url}")
            logging.info(f"Forbidden: {url}")
        elif response.status_code == 404:
            results.append(f"Not Found: {url}")
            logging.info(f"Not Found: {url}")
    except RequestException as e:
        logging.error(f"Error checking {url}: {e}")

def test_http_methods(url, methods, results, user_agent):
    headers = {'User-Agent': user_agent}
    for method in methods:
        try:
            response = requests.request(method, url, headers=headers, timeout=5)
            if response.status_code in [200, 204, 405]:
                results.append(f"{url} - {method} allowed")
                logging.info(f"{url} - {method} allowed")
        except RequestException as e:
            logging.error(f"Error testing {url} with {method}: {e}")

def analyze_response_code(url, results, user_agent):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        status_code = response.status_code
        if status_code == 403:
            results.append(f"{url} - 403 Forbidden")
            logging.info(f"{url} - 403 Forbidden")
        elif status_code == 404:
            results.append(f"{url} - 404 Not Found")
            logging.info(f"{url} - 404 Not Found")
    except RequestException as e:
        logging.error(f"Error analyzing {url}: {e}")

def request_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 429:
                time.sleep(2 ** attempt)  
                continue
            return response
        except RequestException as e:
            logging.error(f"Error on attempt {attempt} for {url}: {e}")
            time.sleep(2 ** attempt)
    return None

def generate_html_report(results, file_name='report.html'):
    template = Template("""
    <html>
    <head><title>Scan Report</title></head>
    <body>
    <h1>Scan Report</h1>
    <ul>
    {% for result in results %}
        <li>{{ result }}</li>
    {% endfor %}
    </ul>
    </body>
    </html>
    """)
    with open(file_name, 'w') as file:
        file.write(template.render(results=results))

def main():
    base_url = input("Enter the URL to scan (including http/https): ")
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    resource_folder = 'resources'
    
    log_filename = configure_logging(base_url)
    
    print("Fetching resources...")
    visited_urls = set()
    urls_to_visit = [base_url]
    resource_urls = set()

    with ThreadPoolExecutor(max_workers=10) as executor:
        while urls_to_visit:
            url = urls_to_visit.pop(0)
            if url in visited_urls:
                continue
            visited_urls.add(url)
            soup = fetch_and_parse(url)
            if soup:
                links = get_all_links(soup, base_url)
                urls_to_visit.extend(links)
                resource_urls.update(links)

    for resource_url in resource_urls:
        download_file(resource_url, resource_folder)
    
    print("Resource capture complete. Check 'resources' folder for downloaded files.")
    
    results = []

    print("Scanning directories...")
    scan_directories(base_url, results, user_agent)
    
    print("Scanning files...")
    scan_files(base_url, results, user_agent)
    
    print("Scanning sensitive files...")
    scan_sensitive_files(base_url, results, user_agent)
    
    print("Testing HTTP methods...")
    HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    test_http_methods(base_url, HTTP_METHODS, results, user_agent)
    
    print("Analyzing response codes...")
    analyze_response_code(base_url, results, user_agent)
    
    print("Scan complete. Results:")
    for result in results:
        print(result)
    
    generate_html_report(results, file_name='report.html')
    
    print("Generating report...")
    

if __name__ == "__main__":
    main()
