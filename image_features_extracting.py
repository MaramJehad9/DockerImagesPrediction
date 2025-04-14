from math import nan
import os
import pandas as pd
import subprocess
import re
from numpy import nan
import requests
import json

# Create a folder to store the text files
scan_images_folder = r'C:\Users\MaramJehad\Downloads\Thesis\scan_images'
os.makedirs(scan_images_folder, exist_ok=True)

def split_docker_image(image_name):
    if ":" in image_name:
        return image_name.split(":")[0]
    else:
        return image_name
    
# Function to search for image names and store results in a list
def search_and_store_images(search_term):
    search_term = split_docker_image(search_term)
    api_url = f"https://hub.docker.com/v2/search/repositories"
    params = {
        "query": search_term,
        "is_automated": "false",
        "is_official": "false",
        "star_count": "3",
        "page_size": "100"
    }

    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        data = response.json().get("results", [])
        image_names = [item["repo_name"] for item in data]
        return image_names
    else:
        print(f"Failed to retrieve images for {search_term}. Status Code: {response.status_code}")
        return []

# Function to perform Docker pull and Snyk scan
def perform_pull_scan(image_name):
    folder_path = r'C:\Users\MaramJehad\Downloads\Thesis\scan_images'
    # Pull Docker image
    subprocess.run(['docker', 'pull', image_name])
    
    # Scan Docker image using Snyk CLI
    scan_output = subprocess.run(['docker', 'scan', image_name], capture_output=True, text=True)
    scan_results = scan_output.stdout.strip()
    # Assuming all_results is a list of strings
    cleaned_img = re.sub(r'\W+', '', image_name)
    scan_file_path = os.path.join(folder_path, f'docker_scan_{cleaned_img}.txt')
    with open(scan_file_path, 'w') as file:
        file.write(scan_results)

    return scan_results

# Function to perform Docker pull and Docker inspect

def perform_inspect(image_name, count):

    # Remove special characters from the image name
    folder_path = r'C:\Users\MaramJehad\Downloads\Thesis\inspect_images'
    cleaned_img = re.sub(r'\W+', '', image_name)

    # Now that the image is available locally, perform Docker inspect
    inspect_cmd = f'docker image inspect {image_name}'
    inspect_output = subprocess.run(inspect_cmd, capture_output=True, text=True)

    # Save the inspect output to a text file
    inspect_file_path = os.path.join(folder_path, f'docker_inspect_{cleaned_img}.txt')
    with open(inspect_file_path, "w") as file:
        file.write(inspect_output.stdout)

    # Parse the inspect output to extract the number of layers
    if inspect_output.returncode == 0 and inspect_output.stdout:
        inspect_json = inspect_output.stdout.strip()
        inspect_data = json.loads(inspect_json)
        print(inspect_data)
        num_layers = len(inspect_data[0]['RootFS']['Layers'])
        # Extract the required features from the image_info dictionary using the get() method
        image_id = inspect_data[0].get('Id')
        architecture = inspect_data[0].get('Architecture')
        created_date = inspect_data[0].get('Created')
        exposed_ports = inspect_data[0]['Config'].get('ExposedPorts')
        env_variables = inspect_data[0]['Config'].get('Env')
        labels = inspect_data[0]['Config'].get('Labels')
        health_check = inspect_data[0]['Config'].get('Healthcheck')
        entrypoint = inspect_data[0]['Config'].get('Entrypoint')
        volumes = inspect_data[0]['Config'].get('Volumes')
        user = inspect_data[0]['Config'].get('User')
        working_dir = inspect_data[0]['Config'].get('WorkingDir')
        cmd = inspect_data[0]['Config'].get('Cmd')
        exposed_directories = inspect_data[0]['Config'].get('ExposedDirs')
        configurations = inspect_data[0]['Config'].get('Config')
        operating_system = inspect_data[0].get('Os')
        author = inspect_data[0].get('Author')
        license_info = inspect_data[0].get('License')
        documentation = inspect_data[0].get('Documentation')

        print('number of images are done : ', count)
        if count == 300:
            removeOT = subprocess.run(['docker image prune -a'])
            count = 0

        return num_layers, image_id, architecture, created_date, exposed_ports, env_variables, labels, health_check, entrypoint, volumes, user, working_dir, cmd, exposed_directories, configurations, operating_system, author, license_info, documentation
    else:
        print(f"Failed to inspect the image: {image_name}")
        return None, None,  None, None,  None, None,  None, None,  None, None, None, None,  None, None,  None, None,  None, None,  None


# Function to search for image names and store results in a list
def search_images(docker_image_name):
    folder_path = r'C:\Users\MaramJehad\Downloads\Thesis\search_images'  
    images_with_tags = []

    # Split the docker_image_name by any special character using regular expression
    special_chars_pattern = r'[^\w]+'  # \w matches any alphanumeric character, [^\w] matches any non-alphanumeric character
    split_results = re.split(special_chars_pattern, docker_image_name)
    for index_split_result in range(0, len(split_results) - 1 ):
        search_cmd = f'docker search {index_split_result}'
        search_output = subprocess.run(search_cmd, shell=True, capture_output=True, text=True, encoding='utf-8')

        # Check if the command executed successfully and there is output
        if search_output.returncode == 0 and search_output.stdout:
            # Split the output into lines and skip the header
            search_lines = search_output.stdout.strip().split('\n')[1:]
            tags = [line.split()[1] for line in search_lines]

            # Step 4: Pull each image along with its respective tag locally
            for tag in tags:
                image_with_tag = f'{docker_image_name}:{tag}'
                images_with_tags.append(image_with_tag)

        cleaned_img = re.sub(r'\W+', '', docker_image_name)
        search_file_path = os.path.join(folder_path, f'docker_search_{cleaned_img}.txt')
        with open(search_file_path, 'w') as file:
            for image_with_tag in images_with_tags:
                file.write(image_with_tag)

        return images_with_tags
    else:
        print(f"Failed to retrieve Docker images for: {docker_image_name}")
        return []
    
def extractSizeTagTime (docker_image_name):
    # Run the command and capture the output
    output = subprocess.run(['docker', 'image', 'ls'], stdout=subprocess.PIPE, text=True).stdout
    if ":" in docker_image_name:
        docker_image_name = docker_image_name.split(":")[0]

    # Split the output into lines
    lines = output.strip().split('\n')
    image_name = ''
    tag = ''
    last_update = ''
    size = ''
    try:
        # Get the header line
        header = lines[0]
        matched_rows = []
        for i in range(len(lines)):
            if i == 0:
                continue
            
            values = lines[i].split()
            if docker_image_name == values[0]:
                    tag = values[1]
                    last_update = values[3] + " " + values[4] 
                    size = values[6]
            
                    return tag, last_update, size
                    
        return tag, last_update, size
    except IndexError:
        return "None", "None", "None"
    
def extract_image_features(image_name, i, count):
    # Read the text file
    try:
        cleaned_img = re.sub(r'\W+', '', image_name)
        scan_folder = r'C:\Users\MaramJehad\Downloads\Thesis\scan_images'
        inspect_folder=r'C:\Users\MaramJehad\Downloads\Thesis\inspect_images\docker_inspect_'
        search_folder=r'C:\Users\MaramJehad\Downloads\Thesis\search_images\docker_search_'
        scan_file_path = os.path.join(scan_folder, f'docker_scan_{cleaned_img}.txt')
        with open(scan_file_path, 'r') as file:
            content = file.read()
            print (' i am extracting the features!*********************************')
            # Extract required information
            data = {}

            content = all_results.split("-------------------------------------------------------")[0]
            docker_name_org = re.search(r'Docker image:\s+(.*)', content)
            if docker_name_org:
                    package_manager = re.search(r'Package manager:\s+(.*)', content)
                    platform = re.search(r'Platform:\s+(.*)', content)
                    base_image = re.search(r'Base image:\s+(.*)', content)
                    noVulnerabilities = re.search(r'no vulnerable paths found.', content)
                    secure_version = re.search(r'According to our scan, you are currently using the most secure version of the selected base image', content)
                    low_severity_count = len(re.findall(r'Low severity vulnerability found', content))
                    medium_severity_count = len(re.findall(r'Medium severity vulnerability found', content))
                    high_severity_count = len(re.findall(r'High severity vulnerability found', content))
                    critical_severity_count = len(re.findall(r'Critical severity vulnerability found', content))
                    base_images_count = len(re.findall(r'Base Image\s+Vulnerabilities\s+Severity', content, flags=re.IGNORECASE))
                    # Extract the number of tested dependencies and vulnerabilities
                    tested_dependencies = re.search(r"Tested (\d+) dependencies for known issues", content)
                    vulnerabilities = re.search(r"found (\d+) issues", content)
                    num_dependencies = 0
                    num_vulnerabilities=0
                    secure_label = ""
                    if tested_dependencies:
                        num_dependencies = int(tested_dependencies.group(1))
                    if vulnerabilities:   
                        num_vulnerabilities = int(vulnerabilities.group(1))
                    else:
                        if noVulnerabilities:
                            num_vulnerabilities = 0

                    # Check for "Recommendations for base image upgrade:" or "Your base image is out of date"
                    if "Recommendations for base image upgrade:" in content or "Your base image is out of date" in content or num_vulnerabilities == 0:
                        secure_label = 0
                    elif secure_version or noVulnerabilities:
                        secure_label = 1
                    elif critical_severity_count == 0 and high_severity_count == 0 and medium_severity_count == 0 :
                        secure_label = 1
                    else:
                        secure_label = 0

                    # Extract the count of alternative base images
                    alternative_base_imgs = re.findall(r"\d+ (?:critical|high|medium|low)", content)
                    docker_name = docker_name_org.group(1) if docker_name_org else None
                    docker_name = docker_name.replace("(", "").replace(")", "").replace("'", "").replace('"', "").replace(",", "").strip() 
                    version_tag, last_updated, size = extractSizeTagTime(docker_name_org.group(1))   
                    if version_tag == 'None' and last_updated == 'None' and size == 'None':
                        return "nothing"
                    data['Docker Name'] = docker_name
                    if(version_tag == "<None>"):
                        version_tag = "latest"
                    data['Tag'] = version_tag
                    data["Last Update"] = last_updated
                    data['Size'] = size
                    data['Package Manager'] = package_manager.group(1) if package_manager else "nan"
                    data['Base Image'] = base_image.group(1) if base_image else "nan"
                    data['# alternative base imgs'] = len(alternative_base_imgs)
                    #data['Platform'] = platform.group(1) if platform.replace("(", "").replace(")", "").replace("'", "").replace('"', "").replace(",", "").strip() else None,
                    data['number of tested dependencies'] = num_dependencies
                    data['number of vulnerabilities'] = num_vulnerabilities
                    data['Critical Severity'] = critical_severity_count
                    data['High Severity'] = high_severity_count
                    data['Medium Severity'] = medium_severity_count
                    data['Low Severity'] = low_severity_count
                    data['Number of Pulls'] = "Nan"
                    data['layers'], data['image_id'], data['architecture'], data['created_date'], data['exposed_ports'], data['env_variables'], data['labels'], data['health_check'], data['entrypoint'], data['volumes'], data['user'], data['working_dir'], data['cmd'], data['exposed_directories'], data['configurations'], data['operating_system'], data['author'], data['license_info'], data['documentation'] = perform_inspect(docker_name, count)
                    data['search'] = search_images(docker_name)
                    data['secure'] = secure_label
                    
                    # Extract the alternative base images
                    base_images = []
                    for line in content.splitlines():
                        if re.search(r"\d+ (?:critical|high|medium|low)$", line):
                            base_image = line.split()[0]
                            base_images.append(base_image)
                    data['name of base images'] = ', '.join(base_images)
                    print(data)
            return data
    except FileNotFoundError:
        print(f"File not found: {file_path}")

def output_results (data):
     
    # Check if the output Excel file already exists
    output_path = r'C:\Users\MaramJehad\Downloads\Thesis\docker_images_pull_scan_inspect_dataset3.xlsx'
    df = pd.DataFrame(data)
    if os.path.exists(output_path):
        # Save the merged DataFrame back to the existing Excel file
        df.to_excel(output_path, index=False)
    else:
        # If the output Excel file does not exist, simply save the new DataFrame to a new Excel file
        df.to_excel(output_path, index=False)
# Read image names from the text file and pull each Docker image
all_results = []
all_data = []
i = 0            # Save results to a text file

for filename in os.listdir(scan_images_folder):
                if filename.endswith('.txt'):
                    file_path = os.path.join(scan_images_folder, filename)
                    with open(file_path, 'r') as file:
                        content = file.read()
                   
                    

# for i, image in df.iterrows():
    # Assuming you have a DataFrame named 'image'
image_name = 'python:3.11' #image['docker image'] + ":" + image['tag']
all_results = perform_pull_scan(image_name)
data = extract_image_features(image_name, i, 1)

if data != "nothing" and isinstance(data, dict):
            all_data.append(data)
            i += 1
            print("DONE!")
            output_results(all_data)
# Create a DataFrame from the extracted data
df = pd.DataFrame(all_data)
