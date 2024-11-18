import requests
import json
import urllib.parse
import warnings
import telnetlib
from concurrent.futures import ThreadPoolExecutor

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
    # URL encode the lab path
    lab_path_encoded = urllib.parse.quote(lab_path)
    response = session.get(f"{base_url}/api/labs{lab_path_encoded}/nodes", verify=False)
    return response.json()

# Main script for powering off vjunosrouter devices
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

            # Store nodes' names, templates, and URLs in a variable for vjunosrouter template only
            nodes_list = []
            for node_id, node in nodes.items():
                if node['template'] == 'vjunosrouter':
                    node_info = {
                        "name": node['name'],
                        "template": node['template'],
                        "url": node['url']
                    }
                    nodes_list.append(node_info)

            # Convert the list of nodes to JSON format and store it in a variable
            nodes_data = {"nodes": nodes_list}

            print("The nodes information has been stored in a variable.")
        else:
            print(f"Error fetching nodes: {nodes_response.get('message')}")
    else:
        print(f"Error fetching labs: {labs_response.get('message')}")
else:
    print(f"Error fetching folders: {folders_response.get('message')}")

# Extract the name, IP, and Port from the nodes data for vjunosrouter template
nodes_info = []
for node in nodes_data['nodes']:
    name = node['name']
    url = node['url']
    ip_port = url.split('//')[1]
    ip, port = ip_port.split(':')
    nodes_info.append((name, ip, port))

# Function to connect to a Juniper vJunos router using telnet and power it off
def power_off_device(name, ip, port):
    try:
        tn = telnetlib.Telnet(ip, port, timeout=10)
        tn.write(b"\n\n")  # Hit enter a couple of times
        tn.read_until(b"login: ", timeout=10)
        tn.write(b"root\n")
        tn.read_until(b"Password: ", timeout=10)
        tn.write(b"juniper1\n")
        tn.read_until(b"root@:~ #", timeout=10)
        tn.write(b"cli\n")
        prompt = tn.read_until(b"> ", timeout=10)
        if b"> " in prompt:
            tn.write(b"request system power-off\n")
        elif b"# " in prompt:
            tn.write(b"run request system power-off\n")
        tn.read_until(b"Power off the system ? [yes,no] (no) ", timeout=10)
        tn.write(b"yes\n")
        tn.read_until(b"> ", timeout=10)
        tn.write(b"exit\n")
        print(f"Successfully powered off {name} at {ip}:{port}")
        tn.close()
    except Exception as e:
        print(f"Failed to power off {name} at {ip}:{port}. Error: {e}")

# Use ThreadPoolExecutor to make the script faster by running tasks concurrently
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(power_off_device, name, ip, port) for name, ip, port in nodes_info]

# Wait for all futures to complete
for future in futures:
    future.result()

print("Script execution completed.")
