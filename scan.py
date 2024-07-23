import argparse
import nmap
import socket
import builtwith
import requests
from bs4 import BeautifulSoup


def scan_open_ports(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"Error resolving domain name {target}: {e}")
        return []

    scanner = nmap.PortScanner()
    scanner.scan(ip_address, "1-1024", arguments="-sV --script=banner")
    open_ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]["state"] == "open":
                    service = scanner[host][proto][port]["name"]
                    version = scanner[host][proto][port].get("product", "unknown")
                    open_ports.append((host, port, service, version))

    return open_ports


def get_technologies(target):
    try:
        technologies = builtwith.parse(f"http://{target}")
        tech_list = []
        for tech_name, tech_info in technologies.items():
            for tech_version in tech_info:
                tech_list.append({"name": tech_name, "version": tech_version})
        return tech_list
    except Exception as e:
        print(f"Error with BuiltWith: {e}")
        return []


def analyze_security_headers(target):
    try:
        url = f"http://{target}"  # Assuming HTTP for simplicity
        response = requests.head(url)
        headers = response.headers

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", ""),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", ""),
            "X-XSS-Protection": headers.get("X-XSS-Protection", ""),
            "Content-Security-Policy": headers.get("Content-Security-Policy", ""),
            # Add more headers as needed
        }

        print(f"Security headers analysis for {target}:")
        for header, value in security_headers.items():
            print(f"{header}: {value}")

        # Evaluate security headers
        print("\nSecurity headers evaluation:")
        for header, value in security_headers.items():
            if header == "Strict-Transport-Security":
                if "max-age" not in value.lower():
                    print(f"- {header} is missing 'max-age' directive.")
                    print(
                        "  Recommendation: Set a 'max-age' value to enforce HTTPS for a specified duration."
                    )
                else:
                    print(f"- {header} directive 'max-age' is properly configured.")
            elif header == "X-Content-Type-Options":
                if value != "nosniff":
                    print(f"- Missing or invalid value for {header}.")
                    print(
                        "  Recommendation: Set 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing."
                    )
                else:
                    print(f"- {header} is correctly set to 'nosniff'.")
            elif header == "X-XSS-Protection":
                if value != "1; mode=block":
                    print(f"- Missing or invalid value for {header}.")
                    print(
                        "  Recommendation: Set 'X-XSS-Protection: 1; mode=block' to enable XSS protection."
                    )
                else:
                    print(f"- {header} is correctly set to '1; mode=block'.")
            elif header == "Content-Security-Policy":
                if not value:
                    print(f"- Missing {header}.")
                    print(
                        "  Recommendation: Implement a Content Security Policy to mitigate XSS and other attacks."
                    )
                else:
                    print(f"- {header} is properly configured: {value}")
            # Add additional checks for other headers as needed

    except requests.exceptions.RequestException as e:
        print(f"Error analyzing security headers for {target}: {e}")


print(
    r"""

███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║██║█████╗  ██║     ██║  ██║███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║███████╗███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                             

    """
)

print(
    "                                                              made by Raghupathi.A"
)


def main():
    parser = argparse.ArgumentParser(description="Network Security Tool")
    args = parser.parse_args()

    while True:

        print("\nNetwork Security Tool Menu")
        print("1. Scan for open ports and detect services")
        print("2. Detect technologies and versions")
        print("3. Analyze security headers of a website")
        print("4. Exit")
        choice = input("Enter your choice (1/2/3/4): ")

        if choice in ["1", "2", "3"]:
            target = input("Enter the target domain name or IP address: ")

        if choice == "1":
            open_ports = scan_open_ports(target)
            if open_ports:
                print(f"Open ports for {target}:")
                for host, port, service, version in open_ports:
                    print(f"Host {host}, Port {port}: {service} (version: {version})")
            else:
                print("No open ports found or error in domain resolution.")

        elif choice == "2":
            technologies = get_technologies(target)
            if technologies:
                print(f"Technologies and versions detected on {target}:")
                for tech in technologies:
                    print(f"{tech['name']}: {tech['version']}")
            else:
                print("Error detecting technologies or no technologies detected.")

        elif choice == "3":
            analyze_security_headers(target)

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
