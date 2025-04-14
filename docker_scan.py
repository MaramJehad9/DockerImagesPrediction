import subprocess
import pandas as pd

import os
import subprocess

# Create a folder to store the text files
folder_path = r''
os.makedirs(folder_path, exist_ok=True)

# Function to perform Docker pull and Snyk scan
def perform_scan(image_name):
    # Pull Docker image
    subprocess.run(['docker', 'pull', image_name])
    
    # Scan Docker image using Snyk CLI
    scan_output = subprocess.run(['docker', 'scan', image_name], capture_output=True, text=True)
    scan_results = scan_output.stdout.strip()

    return scan_results

# List of Docker images to scan
docker_images = ['registry', 'eclipse-temurin', 'websphere-liberty']

# Perform scan for each Docker image and gather results
all_results = []
for image in docker_images:
    scan_results = perform_scan(image)
    all_results.append(scan_results)

    # Save results to a text file
    file_path = os.path.join(folder_path, f'docker_scan_{image}.txt')
    with open(file_path, "w") as file:
        file.write(scan_results)


import re
import os
import re
import pandas as pd

# Define the folder path
folder_path = r''


# Initialize an empty list to store the extracted data
all_data = []

# Iterate over each file in the folder
for filename in os.listdir(folder_path):
    if filename.endswith('.txt'):
        file_path = os.path.join(folder_path, filename)
        
        # Read the text file
        with open(file_path, 'r') as file:
            content = file.read()
        
        # Extract values using regular expressions
        package_manager = re.search(r'Package manager:\s+(.*)', content)
        docker_name = re.search(r'Docker image:\s+(.*)', content)
        platform = re.search(r'Platform:\s+(.*)', content)
        base_image = re.search(r'Base image:\s+(.*)', content)
        vulnerabilities = re.search(r'no vulnerable paths found.', content)
        secure_version = re.search(r'According to our scan, you are currently using the most secure version of the selected base image', content)
        low_severity_count = len(re.findall(r'Low severity vulnerability found', content))
        medium_severity_count = len(re.findall(r'Medium severity vulnerability found', content))
        high_severity_count = len(re.findall(r'High severity vulnerability found', content))
        critical_severity_count = len(re.findall(r'Critical severity vulnerability found', content))
        tested_dependencies = re.search(r'Tested (\d+) dependencies for known issues', content)
        base_image_upgrade = re.search(r'Recommendations for base image upgrade:', content)
        base_images_count = len(re.findall(r'Base Image\s+Vulnerabilities\s+Severity', content, flags=re.IGNORECASE))
        secure_status = 'Yes' if secure_version else 'No'
        
        # Store the extracted data in a dictionary
        data = {
            'File': filename,
            'Package Manager': package_manager.group(1) if package_manager else None,
            'Docker Name': docker_name.group(1) if docker_name else None,
            'Platform': platform.group(1) if platform else None,
            'Base Image': base_image.group(1) if base_image else None,
            '# Vulnerabilities': 0 if vulnerabilities else None,
            'Secure': secure_status,
            'Low Severity': low_severity_count,
            'Medium Severity': medium_severity_count,
            'Critical Severity': critical_severity_count,
            'Tested Dependencies': int(tested_dependencies.group(1)) if tested_dependencies else None,
            'Base Images Count': base_images_count if base_image_upgrade else None
        }
        
        # Append the data to the list
        all_data.append(data)

# Create a DataFrame from the extracted data
df = pd.DataFrame(all_data)


# Specify the file path for the Excel file
excel_file = 'docker_imgs.xlsx'

# Store the DataFrame in an Excel file
df.to_excel(excel_file, index=False)



'''
Package manager:   , Docker image:      , Platform:          , Base image:        ,
 and check if " no vulnerable paths found." is founded in the path will store value in dataframe in column # vulnerabilities = 0
check if this available " According to our scan, you are currently using the most secure version of the selected base image" will store in secure column yes 
count how many "Low severity vulnerability found" and put the count in column called low
count how many "Medium severity vulnerability found" and put the count in column called low
count how many "Critical severity vulnerability found" and put the count in column called low
count how many "High severity vulnerability found" and put the count in column called low

check if "Tested" + digit + " dependencies for known issues" then stor the digits that exists after tested word in column called tetsedDependences
chech if "Recommendations for base image upgrade:" exist in the file
check under this "Recommendations for base image upgrade:" how many image listed under "Base Image      Vulnerabilities  Severity" until those " -------------------------------------------------------" and store their values in "number Base images column", also store in secure column value no
or check how many line ended by "digit critical, digit high, digit medium, digit low"
'''