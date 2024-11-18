from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import os
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed

# Function to scan the network and retrieve a list of active IPs
def scan_network(ip_range, exclude_ip):
    # Initialize the nmap scanner
    scanner = nmap.PortScanner()

    print(f"Scanning the network range {ip_range} excluding {exclude_ip}...")
    
    # Exclude the specified IP (e.g., the host IP running the script)
    exclude_option = f'--exclude {exclude_ip}'
    
    # Perform the scan excluding the specified IP
    scanner.scan(hosts=ip_range, arguments=f'-sn {exclude_option}')  # '-sn' for ping scan

    # Collect active IP addresses
    active_hosts = [host for host in scanner.all_hosts()]

    print(f"Active hosts found: {active_hosts}")
    return active_hosts

# Function to display available folders
def display_folders():
    print("\nAvailable folders for pushing configurations:")
    folders = [f for f in os.listdir() if os.path.isdir(f)]
    for folder in folders:
        print(f" - {folder}")

# Function to get configuration from a device
def get_config(ip, folder_name):
    try:
        dev = Device(host=ip, user='root', passwd='juniper1')
        dev.open()

        hostname = dev.facts['hostname']
        config = dev.rpc.get_config(options={'format': 'text'})

        # Save configuration to file
        file_path = os.path.join(folder_name, f"{hostname}.conf")
        with open(file_path, 'w') as f:
            f.write(config.text)

        dev.close()
        return f"Configuration for {hostname} saved to {file_path}"
    except Exception as e:
        return f"Failed to retrieve configuration from {ip}: {e}"

# Function to push configuration to a device
def push_config(ip, folder_name):
    try:
        dev = Device(host=ip, user='root', passwd='juniper1')
        dev.open()

        hostname = dev.facts['hostname']
        config_file = os.path.join(folder_name, f"{hostname}.conf")

        if not os.path.exists(config_file):
            return f"Configuration file {config_file} not found for {hostname}."

        with Config(dev) as cu:
            cu.load(path=config_file, format="text", overwrite=True)
            cu.commit()

        dev.close()
        return f"Configuration for {hostname} has been pushed and committed."
    except Exception as e:
        return f"Failed to push configuration to {ip}: {e}"

# Main function to execute get or push operations in parallel
def main():
    # Scan the network and get a list of active device IPs
    ip_range = "172.29.129.0/24"  # Adjust this based on your network
    exclude_ip = "172.29.129.254"  # The IP to exclude (host machine)
    device_ips = scan_network(ip_range, exclude_ip)

    # Prompt for action: Get or Push configuration
    action = input("Do you want to 'get' or 'push' configurations? ")

    # Display available folders if action is 'push'
    if action == 'push':
        display_folders()

    # Prompt for folder name
    folder_name = input("Enter the folder name to save/retrieve configurations: ")

    # Create the folder if it doesn't exist (for 'get' operation)
    if action == 'get' and not os.path.exists(folder_name):
        os.makedirs(folder_name)

    # Threading: Use ThreadPoolExecutor to manage threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {}

        # Dispatch tasks for each device
        if action == 'get':
            future_to_ip = {executor.submit(get_config, ip, folder_name): ip for ip in device_ips}
        elif action == 'push':
            future_to_ip = {executor.submit(push_config, ip, folder_name): ip for ip in device_ips}

        # Process results as threads complete
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                print(result)
            except Exception as exc:
                print(f"{ip} generated an exception: {exc}")

if __name__ == "__main__":
    main()
