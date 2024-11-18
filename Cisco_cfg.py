import os
from netmiko import ConnectHandler
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
from concurrent.futures import ThreadPoolExecutor
import nmap


# Function to scan the Cisco network and retrieve IPs with MAC addresses starting with "50:01:00"
def scan_cisco_network():
    scanner = nmap.PortScanner()
    ip_range = "192.168.0.0/24"  # Cisco network range
    print(f"Scanning network {ip_range}...", end=" ")

    try:
        scanner.scan(hosts=ip_range, arguments='-sn -n')  # '-sn' for ping scan, '-n' to skip DNS resolution
        print("done.")
    except Exception as e:
        print(f"Scan failed: {e}")
        return []

    active_ips = []
    for host in scanner.all_hosts():
        mac_address = scanner[host]['addresses'].get('mac', 'N/A')
        if mac_address != 'N/A' and mac_address.startswith("50:01:00"):
            active_ips.append(host)

    if active_ips:
        print(f"Found {len(active_ips)} devices with MAC addresses starting with '50:01:00'.")
    else:
        print("No devices found.")
    
    return active_ips


# Function to save the running config to a local file
def get_config(device, local_folder):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip('#')

        # Retrieve the running config
        print(f"Retrieving config from {hostname}...", end=" ")
        running_config = connection.send_command("show running-config")
        
        # Save to a local file with hostname as the filename
        local_path = os.path.join(local_folder, f"{hostname}.conf")
        with open(local_path, "w") as file:
            file.write(running_config)

        connection.disconnect()
        print(f"Saved config to {local_path}.")
        return hostname, local_path
    except Exception as e:
        print(f"Failed to save config for {device['host']}: {e}")


# Function to list folders in the working directory
def choose_folder(base_folder):
    folders = [f for f in os.listdir(base_folder) if os.path.isdir(os.path.join(base_folder, f))]
    if not folders:
        print("No folders found in the current directory.")
        return None

    print("\nAvailable folders:")
    for idx, folder in enumerate(folders, start=1):
        print(f"{idx}. {folder}")
    
    try:
        choice = int(input("\nSelect a folder by number: ").strip()) - 1
        if 0 <= choice < len(folders):
            return os.path.join(base_folder, folders[choice])
        else:
            print("Invalid choice.")
            return None
    except ValueError:
        print("Invalid input.")
        return None


# Function to upload the config using SCP with retry logic
def upload_file_with_retry(ssh_client, local_path, remote_path, retries=3):
    attempt = 0
    while attempt < retries:
        try:
            with SCPClient(ssh_client.get_transport()) as scp:
                scp.put(local_path, remote_path)
            print("SCP upload successful.")
            return True
        except Exception as e:
            attempt += 1
            print(f"SCP upload failed (attempt {attempt}/{retries}): {e}")
    print("SCP upload failed after retries.")
    return False


# Function to push the configuration to the devices
def push_config(device, local_folder):
    try:
        # Connect to the device using Paramiko
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        ssh_client.connect(
            hostname=device['host'],
            username=device['username'],
            password=device['password'],
            allow_agent=False,
            look_for_keys=False,
            timeout=30  # Increased SSH connection timeout
        )

        # Retrieve the hostname for the device
        netmiko_conn = ConnectHandler(**device)
        hostname = netmiko_conn.find_prompt().strip('#')
        netmiko_conn.disconnect()

        # Local config file path
        local_path = os.path.join(local_folder, f"{hostname}.conf")
        if not os.path.isfile(local_path):
            print(f"Config file for {hostname} not found in {local_folder}.")
            return

        print(f"Uploading config to {hostname}...", end=" ")

        # Upload the file using SCP with retry logic
        if not upload_file_with_retry(ssh_client, local_path, f"flash:/{hostname}.conf"):
            print(f"Failed to upload config to {hostname}. Skipping.")
            return

        # Verify the file exists in the flash directory
        netmiko_conn = ConnectHandler(**device)
        cmd_verify = f"dir flash:/{hostname}.conf"
        output = netmiko_conn.send_command(cmd_verify, delay_factor=2)
        if f"{hostname}.conf" not in output:
            print(f"File not found in flash: on {hostname}.")
            return

        print("File verified in flash:.", end=" ")

        # Replace the running configuration with the uploaded config
        netmiko_conn.send_command_timing(f"copy flash:/{hostname}.conf running-config", delay_factor=2)
        netmiko_conn.send_command_timing("\n")  # Confirm the overwrite
        netmiko_conn.disconnect()

        print(f"Running configuration replaced on {hostname}.")
        ssh_client.close()

    except Exception as e:
        print(f"Failed to push config to {device['host']}: {e}")


# Main function to retrieve configurations
def main():
    # Automatically set base folder to the script's current directory
    base_folder = os.getcwd()

    # Ask for the folder to save configurations
    folder_name = input(f"Enter the folder name to save configs: ").strip()
    local_folder = os.path.join(base_folder, folder_name)

    # Create the folder if it doesn't exist
    os.makedirs(local_folder, exist_ok=True)

    # Scan the network to get the active IPs
    active_ips = scan_cisco_network()
    if not active_ips:
        print("No active devices found.")
        return

    # Use ThreadPoolExecutor for parallel configuration retrieval
    with ThreadPoolExecutor(max_workers=5) as executor:
        tasks = [executor.submit(get_config, {
            'device_type': 'cisco_ios',
            'username': 'admin',
            'password': 'cisco123',
            'secret': 'cisco123',
            'host': ip
        }, local_folder) for ip in active_ips]

        # Wait for all threads to complete
        for task in tasks:
            task.result()


# Main function to push configurations
def main_push():
    base_folder = os.getcwd()

    # Step 1: Choose folder
    local_folder = choose_folder(base_folder)
    if not local_folder:
        return

    # Step 2: Scan network to identify devices
    active_ips = scan_cisco_network()
    if not active_ips:
        print("No active devices found.")
        return

    # Step 3: Push configuration to each device
    with ThreadPoolExecutor(max_workers=5) as executor:
        tasks = [executor.submit(push_config, {
            'device_type': 'cisco_ios',
            'username': 'admin',
            'password': 'cisco123',
            'secret': 'cisco123',
            'host': ip
        }, local_folder) for ip in active_ips]

        # Wait for all threads to complete
        for task in tasks:
            task.result()


if __name__ == "__main__":
    while True:
        print("\nOptions:")
        print("1. Retrieve running configurations")
        print("2. Push configurations to devices")
        print("3. Exit")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            main()
        elif choice == "2":
            main_push()
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("Invalid option. Please choose again.")
