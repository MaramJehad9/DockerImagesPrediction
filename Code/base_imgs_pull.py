
from math import nan
import os
import pandas as pd
import subprocess
import re
from numpy import nan
import requests


# Create a folder to store the text files
folder_path = r''
os.makedirs(folder_path, exist_ok=True)

# Function to search for image names and store results in a list
def search_and_store_images(search_term):
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
    # Pull Docker image
    subprocess.run(['docker', 'pull', image_name])
    
    # Scan Docker image using Snyk CLI
    scan_output = subprocess.run(['docker', 'scan', image_name], capture_output=True, text=True)
    scan_results = scan_output.stdout.strip()

    return scan_results

def extractSizeTagTime (docker_image_name):
    # Run the command and capture the output
    output = subprocess.run(['docker', 'image', 'ls'], stdout=subprocess.PIPE, text=True).stdout

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
def extract_image_features(all_results, i, file_path, version):
    # Read the text file
    try:
        with open(file_path, 'r') as file:
            content = file.read()

            # Extract required information
            data = {}

            # Extract the part of the file until the first "-------------------------------------------------------"
            content = content.split("-------------------------------------------------------")[0]
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
                        secure_label = 'No'
                    elif secure_version:
                        secure_label = 'Yes'
                    elif noVulnerabilities:
                        secure_label = 'Yes'
                    elif num_vulnerabilities == 0:
                        secure_label = 'Yes'
                    else:
                        secure_label = 'No'

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
                    data['Tag'] = version
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
                    data['secure'] = secure_label
                    
                    # Extract the alternative base images
                    base_images = []
                    for line in content.splitlines():
                        if re.search(r"\d+ (?:critical|high|medium|low)$", line):
                            base_image = line.split()[0]
                            base_images.append(base_image)
                    data['name of base images'] = ', '.join(base_images)
                
        return data
    except FileNotFoundError:
        print(f"File not found: {file_path}")


all_results = []
all_data = []
i = 0


def extract_versions(docker_images):
    versions = []
    for image in docker_images:
        # Split the image name and version by the colon ":"
        parts = image.split(":")
        if len(parts) > 1:
            versions.append(parts[1])
        else:
            versions.append("latest")  # If no version is provided, use "latest"
    return versions

if __name__ == "__main__":
    docker_images_array = [
    "openjdk:7-jre", "openjdk:11.0-jre", "openjdk:21-ea-31-jdk-slim", "openjdk:22-ea-6-jdk-slim", "openjdk:21-ea-30-jdk-slim", "openjdk:22-ea-5-jdk-slim",
    "ubuntu:focal-20210217", "ubuntu:focal-20230605", "ubuntu:lunar-20230615",
    "alpine:3.7", "alpine:3.14",
    "debian:11.2-slim", "debian:bullseye-20230612-slim", "debian:bookworm-20230612-slim",
    "debian:stretch-20181011-slim", "debian:bookworm-20230612-slim",
    "ubuntu:16.04", "ubuntu:xenial-20210416", "ubuntu:lunar-20230615",
    "centos:7.7.1908", "centos:7", "centos:centos8",
    "debian:9.13-slim", "debian:bookworm-20230612-slim",
    "debian:10.13-slim", "debian:bookworm-20230612-slim",
    "centos:centos7.9.2009", "centos:centos8",
    "amazonlinux:2.0.20230612.0", "amazonlinux:2.0.20230628.0",
    "ubuntu:16.04", "ubuntu:xenial-20210416", "ubuntu:lunar-20230615",
    "ubuntu:18.04", "ubuntu:lunar-20230615",
    "centos:8.1.1911", "centos:centos8",
    "debian:10.13-slim", "debian:bookworm-20230612-slim",
    "amazonlinux:2.0.20230612.0", "amazonlinux:2.0.20230628.0",
    "ubuntu:bionic-20181112", "ubuntu:bionic", "ubuntu:lunar-20230615",
    "debian:10.10-slim", "debian:buster-20230703-slim", "debian:bookworm-20230612-slim",
    "debian:stretch-20190326-slim", "debian:bookworm-20230612-slim",
    "ubuntu:22.04", "ubuntu:kinetic", "ubuntu:lunar-20230615",
    "rockylinux:8.8.20230518", "rockylinux:9.2", "rockylinux:8.8-minimal",
    "golang:1.14.3-buster", "golang:1.19.10-buster", "golang:1.20.5-bookworm", "golang:1.21rc3-bullseye", "golang:1.19-rc", "golang:1.19-rc-buster",
    "ubuntu:18.04", "ubuntu:lunar-20230615",
    "centos:centos7.9.2009", "centos:centos8",
    "debian:jessie-20180426", "debian:bookworm-20230612", "debian:bookworm-20230612-slim",
    "openjdk:17.0.2-slim-bullseye", "openjdk:21-ea-31-jdk-slim", "openjdk:22-ea-6-jdk-slim", "openjdk:21-ea-30-jdk-slim", "openjdk:22-ea-5-jdk-slim"]

    # Step 1: Create a list of Docker images from the provided text
    docker_images = [img.strip() for img in docker_images_array]

    # Step 2: Remove duplicates from the list
    docker_images = list(set(docker_images))

    # Step 3: Split each Docker image to separate the name and version
    docker_image_names = []
    for image in docker_images:
        parts = image.split(":")
        if len(parts) > 1:
            docker_image_names.append(parts[0])
        else:
            docker_image_names.append(image)

    # Step 4: Store the versions in separate arrays
    versions_dict = {}
    for name in docker_image_names:
        versions_dict[name] = []

    for image in docker_images:
        parts = image.split(":")
        name = parts[0]
        version = parts[1] if len(parts) > 1 else "latest"

        #versions_dict[name].append(version)

        scan_results =  perform_pull_scan(image)
        all_results.append(scan_results)
        cleaned_img = re.sub(r'\W+', '', name)
        # Save results to a text file
        file_path = os.path.join(folder_path, f'docker_scan_{cleaned_img}.txt')
        with open(file_path, "w") as file:
            file.write(scan_results)
        data = extract_image_features(all_results, i, file_path, version)
        if data != "nothing" and isinstance(data, dict):
            all_data.append(data)
            i += 1
# Create a DataFrame from the extracted data
df = pd.DataFrame(all_data)

output_path = r'docker_base_images_dataset.xlsx'
df.to_excel(output_path, index=False)





    