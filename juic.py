import csv
import xml.etree.ElementTree as ET
import sys
import os

def analyze_nessus_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    host_data = {}

    for report in root.findall(".//Report"):
        for host in report.findall(".//ReportHost"):
            ip_address = host.get("name")
            host_data[ip_address] = set()

            for item in host.findall(".//ReportItem"):
                port = item.get("port")
                protocol = item.get("protocol")
                service = item.get("svc_name")
                host_data[ip_address].add((port, protocol, service))

    return host_data

def generate_csv(host_data, file_name):
    csv_filename = os.path.splitext(file_name)[0] + ".csv"

    with open(csv_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Host', 'Port'])

        for host, data in host_data.items():
            ports = ','.join([port for port, _, _ in data if port != "0"])
            writer.writerow([host, ports])

    print("CSV file generated successfully: {}".format(csv_filename))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 taukir.py <nessus_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    file_name = os.path.basename(file_path)
    host_data = analyze_nessus_file(file_path)
    generate_csv(host_data, file_name)