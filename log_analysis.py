import re
import csv
from collections import defaultdict

# Configuration
FAILED_LOGIN_THRESHOLD = 10


# Functions
def parse_log_file(log_file):
    """Parses the log file and extracts relevant data."""
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP Address
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract Endpoint
            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) (.*?) HTTP/1\.\d"', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access[endpoint] += 1

            # Detect Failed Login Attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_access, failed_logins


def count_requests_per_ip(ip_requests):
    """Counts requests per IP and sorts them in descending order."""
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)


def most_accessed_endpoint(endpoint_access):
    """Finds the most accessed endpoint."""
    if not endpoint_access:  # Check if the dictionary is empty
        return None, 0
    return max(endpoint_access.items(), key=lambda x: x[1])


def detect_suspicious_activity(failed_logins, threshold):
    """Detects IPs with failed login attempts exceeding the threshold."""
    return {ip: count for ip, count in failed_logins.items() if count > threshold}


def save_to_csv(ip_requests, endpoint, suspicious_activities, output_file):
    """Saves the analysis results to a CSV file."""
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write IP Request Counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if endpoint[0]:  # Check if an endpoint exists
            writer.writerow([endpoint[0], endpoint[1]])
        else:
            writer.writerow(["None", 0])

        # Write Suspicious Activities
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])


def main():
    # File paths
    log_file = "sample.log"
    output_file = "log_analysis_results.csv"

    # Parse log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(log_file)

    # Analysis
    ip_requests_sorted = count_requests_per_ip(ip_requests)
    most_frequent_endpoint = most_accessed_endpoint(endpoint_access)
    suspicious_activities = detect_suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)

    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests_sorted:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_frequent_endpoint[0]:  # Check if there is a valid endpoint
        print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")
    else:
        print("No endpoints found.")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests_sorted, most_frequent_endpoint, suspicious_activities, output_file)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()

