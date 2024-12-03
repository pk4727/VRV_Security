import csv

# Default Threshold for suspicious activity (Given in description)
FAILED_LOGIN_THRESHOLD = 10

# Reads the log file and returns the lines.
def parse_log_file(file_path): 
    with open(file_path, 'r') as file:
        return file.readlines()

# Counts requests for each IP address.
def count_requests_per_ip(logs):
    ip_counts = {}
    for log in logs:
        ip = log.split(' ')[0]
        if ip in ip_counts:
            ip_counts[ip] += 1
        else:
            ip_counts[ip] = 1
    return ip_counts

# Finds the most frequently accessed endpoint.
def most_frequently_accessed_endpoint(logs):
    endpoint_counts = {}
    for log in logs:
        parts = log.split('"')
        if len(parts) > 1:
            request = parts[1].split(' ')
            if len(request) > 1:
                endpoint = request[1]
                if endpoint in endpoint_counts:
                    endpoint_counts[endpoint] += 1
                else:
                    endpoint_counts[endpoint] = 1

    most_accessed = max(endpoint_counts, key=endpoint_counts.get, default=None)
    return most_accessed, endpoint_counts[most_accessed]

# Finds IPs with many failed login attempts.
def detect_suspicious_activity(logs):
    failed_attempts = {}
    for log in logs:
        if ' 401 ' in log or "Invalid credentials" in log:
            ip = log.split(' ')[0]
            if ip in failed_attempts:
                failed_attempts[ip] += 1
            else:
                failed_attempts[ip] = 1

    suspicious_IP_Addresses = {}
    for ip, count in failed_attempts.items():
        if count > FAILED_LOGIN_THRESHOLD:
            suspicious_IP_Addresses[ip] = count
    return suspicious_IP_Addresses

# Saves results to a CSV file.
def save_result_to_csv(ip_counts, most_accessed, suspicious_IP_Addresses):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Section 1: Write Requests per IP Address
        writer.writerow(['Requests per IP Address:-'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Section 2: Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint:-'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Section 3: Write Detect Suspicious Activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity:-'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_IP_Addresses.items():
            writer.writerow([ip, count])

def main():
    log_file = 'sample.log'
    logs = parse_log_file(log_file)
    
    # Analyze logs
    ip_counts = count_requests_per_ip(logs)
    sorted_ip_counts = dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True))
    most_accessed = most_frequently_accessed_endpoint(logs)
    suspicious_IP_Addresses = detect_suspicious_activity(logs)

    # save result to csv file
    save_result_to_csv(sorted_ip_counts, most_accessed, suspicious_IP_Addresses)
    
    # Display results
    print("Requests per IP Address:")
    print('IP Address          Request Count')
    for ip, count in sorted_ip_counts.items():
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_IP_Addresses:
        print("IP Address          Failed Login Attempts")
        for ip, count in suspicious_IP_Addresses.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")

if __name__ == '__main__':
    main()
