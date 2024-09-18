# Security Scan Web Application

This is a web application for performing security scans on URLs. The application allows users to enter a URL, which is then scanned, and the results are displayed in a visually appealing way. The scan results include a score and detailed information about the scan.

## Features

- Enter a URL to perform a security scan.
- Display scan results with a score and detailed information.
- User-friendly interface with a warm white background.

## Technologies Used

- HTML, CSS, JavaScript for the frontend.
- Python and Flask for the backend.
- Nmap for security scanning.

## Setup Instructions

### Prerequisites

- Python 3.9 or higher

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/MananUkani/WebScrap.git
   cd WebScrap
2.**Create a virtual environment**

  ```bash
  python -m venv venv
  source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```
3.**Install Dependancies**
 pip install -r requirements.txt

 
**Usage**
Open your web browser and navigate to http://localhost:5000.
Enter the URL you want to scan in the input field and click the “Scan” button.
View the scan results, including the score and detailed information.


**Project Structure**

app.py: The main Flask application file.
templates/index.html: The HTML template for the web interface.
static/: Directory for static files (CSS, JavaScript).
requirements.txt: List of Python dependencies.


**Contributing**

Contributions are welcome! Please fork the repository and submit a pull request.

**Acknowledgements**

Flask
Nmap


Made by Manan Ukani
