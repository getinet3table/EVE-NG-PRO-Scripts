import requests
import json
import urllib.parse
import warnings
import telnetlib
from concurrent.futures import ThreadPoolExecutor
import time 

# Suppress only the single InsecureRequestWarning from urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Define base URL and credentials
base_url = "https://192.168.0.53"
username = "Alin"
password = "Alin2000"

# Function to authenticate and get cookies
def login(base_url, username, password):
    session = requests.Session()  # Create a session
    response = session.post(f"{base_url}/api/auth/login",
                             json={"username": username, "password": password, "html5": "0"},
                             verify=False)
    if response.status_code == 200 and response.json().get("code") == 200:
        print("Logged in successfully.")
        return session  # Return the session with cookies
    else:
        print("Login failed.")
        return None

# Function to get available folders
def get_folders(session, base_url):
    response = session.get(f"{base_url}/api/folders/", verify=False)
    return response.json()

# Function to get labs in a specific folder
def get_labs_in_folder(session, base_url, folder_path):
    response = session.get(f"{base_url}/api/folders{folder_path}", verify=False)
    return response.json()

# Function to get nodes in a specific lab
def get_nodes_in_lab(session, base_url, lab_path):
    lab_path_encoded = urllib.parse.quote(lab_path)
    response = session.get(f"{base_url}/api/labs{lab_path_encoded}/nodes", verify=False)
    return response.json()

# Main script for EVE-NG API interaction
session = login(base_url, username, password)
if session is None:
    exit()

# Get available folders
folders_response = get_folders(session, base_url)
if folders_response.get("code") == 200:
    folders = folders_response.get("data", {}).get("folders", [])

    print("\nAvailable Folders:")
    for index, folder in enumerate(folders):
        print(f"{index + 1}. {folder['name']} (Path: {folder['path']})")

    folder_index = int(input("\nSelect a folder by number: ")) - 1
    selected_folder = folders[folder_index]['path']

    # Get labs in the selected folder
    labs_response = get_labs_in_folder(session, base_url, selected_folder)
    if labs_response.get("code") == 200:
        labs = labs_response.get("data", {}).get("labs", [])

        print(f"\nAvailable Labs in '{selected_folder}':")
        for index, lab in enumerate(labs):
            print(f"{index + 1}. {lab['file']} (Path: {lab['path']})")

        lab_index = int(input("\nSelect a lab by number: ")) - 1
        selected_lab = labs[lab_index]['path']  # Use 'path' to get the lab's path

        # Get nodes in the selected lab
        nodes_response = get_nodes_in_lab(session, base_url, selected_lab)

        # Handle nodes response
        if nodes_response.get("code") == 200:
            nodes = nodes_response.get("data", {})

            # Categorize nodes by their templates
            juniper_nodes = []
            cisco_nodes = []

            for node_id, node in nodes.items():
                node_info = {
                    "name": node['name'],
                    "template": node['template'],
                    "url": node['url']
                }

                if node['template'] in ['vmxvcp', 'vjunosrouter']:
                    juniper_nodes.append(node_info)
                elif node['template'] == 'vios':
                    cisco_nodes.append(node_info)

            # Store categorized nodes
            juniper_nodes_data = {"nodes": juniper_nodes}
            cisco_nodes_data = {"nodes": cisco_nodes}

            print("\nNodes categorized into Juniper and Cisco lists.")
        else:
            print(f"Error fetching nodes: {nodes_response.get('message')}")
    else:
        print(f"Error fetching labs: {labs_response.get('message')}")
else:
    print(f"Error fetching folders: {folders_response.get('message')}")

# Ask the user whether they want to configure only Cisco or only Juniper devices
device_choice = input("\nDo you want to configure (C)isco or (J)uniper devices? (Enter C/J): ").strip().lower()

# Configure Juniper devices if the user selects 'j'
if device_choice == 'j':
    juniper_nodes_info = []
    for node in juniper_nodes_data['nodes']:
        name = node['name']
        url = node['url']
        ip_port = url.split('//')[1]
        ip, port = ip_port.split(':')
        juniper_nodes_info.append((name, ip, port))

    def configure_juniper_device(name, ip, port):
        try:
            tn = telnetlib.Telnet(ip, port, timeout=10)
            tn.write(b"\n\n")  # Hit enter a couple of times
            time.sleep(1)
            tn.write(b"\n\n")  # Hit enter a couple of times
            time.sleep(1)
            tn.read_until(b"login: ", timeout=10)
            tn.write(b"root\n")
            tn.read_until(b"root@:~ #", timeout=10)
            tn.write(b"cli\n")
            tn.read_until(b"> ", timeout=10)
            tn.write(b"edit\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(f"set system host-name {name}\n".encode('ascii'))
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set system root-authentication plain-text-password\n")
            tn.read_until(b"New password: ", timeout=10)
            tn.write(b"juniper1\n")
            tn.read_until(b"Retype new password: ", timeout=10)
            tn.write(b"juniper1\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"delete chassis auto-image-upgrade\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set system services ssh root-login allow\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set system services ssh sftp-server\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set system services netconf ssh\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set system management-instance\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 172.29.129.254\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"delete interfaces fxp0.0 family inet6\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"delete protocols router-advertisement\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set chassis network-services enhanced-ip\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"set chassis aggregated-devices ethernet device-count 10\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"delete system processes dhcp-service\n")
            tn.read_until(b"# ", timeout=10)
            tn.write(b"commit and-quit\n")
            tn.read_until(b"> ", timeout=10)
            tn.write(b"exit\n")
            print(f"Successfully configured {name} at {ip}:{port}")
            tn.close()
        except Exception as e:
            print(f"Failed to configure Juniper device {name} at {ip}:{port}. Error: {e}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(configure_juniper_device, name, ip, port) for name, ip, port in juniper_nodes_info]
    for future in futures:
        future.result()

# Configure Cisco devices if the user selects 'c'
elif device_choice == 'c':
    cisco_nodes_info = []
    for node in cisco_nodes_data['nodes']:
        name = node['name']
        url = node['url']
        ip_port = url.split('//')[1]
        ip, port = ip_port.split(':')
        cisco_nodes_info.append((name, ip, port))

    def configure_cisco_device(name, ip, port):
        try:
            tn = telnetlib.Telnet(ip, port, timeout=10)
            tn.write(b"\n\n")  # Hit enter a couple of times
            time.sleep(1)
            tn.write(b"\n\n")  # Hit enter a couple of times
            time.sleep(1)
            tn.write(b"\n\n")  # Hit enter a couple of times
            time.sleep(1)
            tn.write(b"\n\n")  # Hit enter a couple of times
            tn.write(b"\n\n")  # Hit enter a couple of times
            tn.write(b"\n\n")  # Hit enter a couple of times
            tn.write(b"\n\n")  # Hit enter a couple of times
            time.sleep(1)
            tn.read_until(b">", timeout=10)
            tn.write(b"enable\n")
            tn.read_until(b"#", timeout=10)
            tn.write(b"configure terminal\n")
            tn.read_until(b"(config)#", timeout=10)
            tn.write(f"hostname {name}\n".encode('ascii'))
            tn.read_until(b"(config)#", timeout=10)
            tn.write(b"interface gi0/0\n")
            tn.read_until(b"(config-if)#", timeout=10)
            tn.write(b"ip address dhcp\n")
            tn.read_until(b"(config-if)#", timeout=10)
            tn.write(b"no shutdown\n")
            tn.read_until(b"(config-if)#", timeout=10)
            tn.write(b"exit\n")
            tn.read_until(b"(config)#", timeout=10)
            tn.write(b"ip domain-name eve-ng.com\n")
            tn.read_until(b"(config)#", timeout=10)
            tn.write(b"username admin privilege 15 password cisco123\n")
            tn.read_until(b"(config)#", timeout=10)
            tn.write(b"line vty 0 4\n")
            tn.read_until(b"(config-line)#", timeout=10)
            tn.write(b"transport input ssh\n")
            tn.read_until(b"(config-line)#", timeout=10)
            tn.write(b"login local\n")
            tn.read_until(b"(config-line)#", timeout=10)
            tn.write(b"exit\n")
            tn.read_until(b"(config)#", timeout=10)
            tn.write(b"crypto key generate rsa\n")
            tn.read_until(b"The name for the keys will be: ", timeout=10)
            tn.write(f"{name}.eve-ng.com\n".encode('ascii'))
            tn.read_until(b"How many bits in the modulus [512]: ", timeout=10)
            tn.write(b"2048\n")
            tn.read_until(b"% Generating 2048 bit RSA keys", timeout=60)
            tn.read_until(b"[OK]", timeout=60)
            tn.write(b"ip ssh version 2\n")
            tn.write(b"no ip domain lookup\n")
            tn.write(b"enable secret cisco123\n")
            tn.write(b"ip scp server enable\n")
            tn.read_until(b"(config)#", timeout=10)
            tn.write(b"end\n")
            tn.read_until(b"#", timeout=10)
            tn.write(b"write memory\n")
            tn.write(b"copy running-config flash:\n")
            tn.read_until(b"Destination filename [running-config]?", timeout=10)
            tn.write(b"initcfg\n")
            tn.read_until(b"#", timeout=10)
            tn.write(b"exit\n")
            print(f"Successfully configured {name} at {ip}:{port}")
            tn.close()
        except Exception as e:
            print(f"Failed to configure Cisco device {name} at {ip}:{port}. Error: {e}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(configure_cisco_device, name, ip, port) for name, ip, port in cisco_nodes_info]
    for future in futures:
        future.result()

else:
    print("Invalid input! Please enter 'C' for Cisco or 'J' for Juniper.")
