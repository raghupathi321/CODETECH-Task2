Name:APPALA RAGHUPATHI<br>
Company:CODTECH IT SOLUTIONS<br>
ID:CT08DS3280<br>
DOMAIN: CYBER SECURITY & ETHICAL HACKING<br>
DURATION:4 WEEKS (JUNE 25 th to JULY 25 th)<br>
MENTOR:Neela Santhosh Kumar<br>



# Vulnerability Scanning Tool

## Overview

The Vulnerability Scanning Tool is a comprehensive security tool designed to help identify potential vulnerabilities within a network or web application. The tool performs various security checks, including open port scanning, version detection, tech stack identification, and HTTP header misconfiguration analysis.

## Features

### Open Port Scanning
The tool scans the target network for open ports, providing a detailed list of accessible ports and their status. This helps in identifying unnecessary open ports that could be potential entry points for attackers.

### Version Detection
The tool detects the versions of the services running on the open ports. Knowing the specific versions can help in identifying known vulnerabilities associated with those versions.

### Tech Stack Identification
The tool identifies the technology stack used by the target web application, including server software, programming languages, frameworks, and other components. This information is crucial for understanding the potential attack surface.

### HTTP Header Misconfiguration Analysis
The tool analyzes the HTTP headers of the target web application to detect any misconfigurations or missing security headers. Properly configured headers are essential for protecting against common web attacks.

## Usage

1. **Installation**: Clone the repository and install the required dependencies.
   ```sh
   git clone <repository_url>
   cd vulnerability-scanning-tool
   pip install -r requirements.txt
   ```

2. **Configuration**: Modify the configuration file to set the target network or web application details.

3. **Running the Tool**: Execute the tool using the command line.
   ```sh
   python scan.py --target <target_url_or_ip>
   ```

4. **Results**: View the detailed scan results in the generated report, which includes information on open ports, service versions, tech stack, and HTTP header analysis.

## Technologies Used

- **Programming Language**: Python
- **Libraries**: `nmap`, `requests`, `BeautifulSoup`, `scapy`
- **Frameworks**: Flask (for web interface)
- **Tools**: `Nmap` (for network scanning), `Wappalyzer` (for tech stack identification)

---

