import re
from collections import Counter
from jnpr.junos import Device
from jnpr.junos.utils.config import Config

# Path to the log file
log_file_path = '/var/log/messages'  # Adjust the path if necessary

# Regular expression to match the failed login log entries
log_pattern = re.compile(r"SSHD_LOGIN_FAILED: Login failed for user .+ from host '(\d+\.\d+\.\d+\.\d+)'")

# Initialize a list to store IP addresses
failed_logins = []

# Open and read the log file
try:
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            match = log_pattern.search(line)
            if match:
                ip = match.group(1)
                failed_logins.append(ip)
except Exception as e:
    print(f"Error reading log file: {str(e)}")

# Count occurrences of each IP address
ip_counter = Counter(failed_logins)

# Find the most frequent offending IP
if ip_counter:
    offending_ip, count = ip_counter.most_common(1)[0]
    print(f"The IP address with the most failed SSH login attempts is {offending_ip} with {count} attempts.")
    if count > 3:  # Threshold
        print(f"Blocking IP {offending_ip} after {count} failed login attempts")

        # Firewall filter configuration commands
        firewall_commands = [
            f"set firewall family inet filter block-offending-ips term block-ip from source-address {offending_ip}/32",
            "set firewall family inet filter block-offending-ips term block-ip then discard"
        ]

        # Apply the configuration using Junos PyEZ
        try:
            # Replace 'username' and 'password' with appropriate values
            print("enterred try block")
            with Device(host= '10.85.242.4', user='labroot', passwd='lab123') as dev:
                print("entered with Device")
                with Config(dev, mode='exclusive') as cu:
                    print("entered config")
                    for command in firewall_commands:
                        print(f"Applying command: {command}")
                        cu.load(command, format='set')
                    cu.commit()
            print(f"Successfully blocked IP {offending_ip}.")
        except Exception as e:
            print(f"Error applying firewall filter: {str(e)}")
else:
    print("No SSHD_LOGIN_FAILED entries found in the log file.")

# Optional: Print all IPs and their counts
print("\nAll IPs and their counts:")
for ip, count in ip_counter.items():
    print(f"{ip}: {count}")


