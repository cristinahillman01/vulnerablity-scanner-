"""
Beginner Python Port Scanner

Purpose:
A learning project to understand basic network security concepts.

IMPORTANT:
Only scan computers, servers, or networks you own
or have permission to test.
"""


import socket
from datetime import datetime


# Common ports and their usual services
PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP Email",
    53: "DNS",
    80: "HTTP Web",
    110: "POP3 Email",
    139: "Windows File Sharing",
    443: "HTTPS Secure Web",
    445: "SMB File Sharing",
    8080: "Alternative Web"
}


# Scan a single port
def scan_port(target, port):

    try:

        scanner = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        scanner.settimeout(1)

        result = scanner.connect_ex(
            (target, port)
        )


        if result == 0:

            print(
                f"[OPEN] {port} - {PORTS[port]}"
            )

            banner = get_banner(
                scanner
            )

            if banner:
                print(
                    f"       Service: {banner}"
                )

            return True


        else:

            print(
                f"[CLOSED] {port}"
            )


        scanner.close()


    except Exception as error:

        print(
            f"Error scanning port {port}: {error}"
        )


    return False



# Try to identify the service
def get_banner(scanner):

    try:

        scanner.send(
            b"HEAD / HTTP/1.1\r\n\r\n"
        )

        banner = scanner.recv(
            1024
        )

        return banner.decode(
            errors="ignore"
        ).strip()


    except:

        return None



# Save results
def save_report(target, results):

    filename = "scan_report.txt"


    with open(filename, "w") as file:

        file.write(
            "Python Port Scanner Report\n"
        )

        file.write(
            "=========================\n\n"
        )

        file.write(
            f"Target: {target}\n"
        )

        file.write(
            f"Date: {datetime.now()}\n\n"
        )


        for result in results:

            file.write(
                result + "\n"
            )


    print(
        f"\nReport saved as {filename}"
    )



# Main program
def main():

    print(
        """
================================
 Beginner Python Port Scanner
================================

Only scan authorised systems.
"""
    )


    target = input(
        "Enter target IP address: "
    )


    print(
        "\nStarting scan..."
    )

    print(
        "Target:",
        target
    )

    print(
        "Time:",
        datetime.now()
    )


    results = []


    for port in PORTS:

        open_port = scan_port(
            target,
            port
        )


        if open_port:

            results.append(
                f"Port {port} OPEN - {PORTS[port]}"
            )


    print(
        "\nScan Complete"
    )


    save_report(
        target,
        results
    )



# Run program
if __name__ == "__main__":

    main()