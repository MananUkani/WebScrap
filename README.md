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


**Screenshots**
![image](https://github.com/user-attachments/assets/c1e39e35-03cd-4ce4-91c5-949e8b1a3502)
![image](https://github.com/user-attachments/assets/e3bdc07d-67b7-48a8-a243-784cc1667242)
![image](https://github.com/user-attachments/assets/85c61805-cca1-4e06-9718-a1820796256b)
![image](https://github.com/user-attachments/assets/d79e5fb5-9ecd-41dd-be5a-698ba4728e14)
![image](https://github.com/user-attachments/assets/68717cb5-f6a9-49ca-91ac-a36c67917291)



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
