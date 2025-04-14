import pandas as pd
import subprocess
import os
import re
import json

# Load the Excel file into a DataFrame
excel_file_path = r''
excel_file_path = r''
df = pd.read_excel(excel_file_path)

# Create a folder to store the inspect text files
folder_path = r''
os.makedirs(folder_path, exist_ok=True)
count = 0

# Function to perform Docker pull and Docker inspect
def perform_pull_inspect(image_name):
    # Remove special characters from the image name
    cleaned_img = re.sub(r'\W+', '', image_name)
    print(cleaned_img)

    pull_output = subprocess.run(['docker', 'pull', image_name])
    if pull_output.returncode != 0:
        return None, None

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
        num_layers = len(inspect_data[0]['RootFS']['Layers'])
        print(num_layers, inspect_data)
        if count == 200:
            removeOT = subprocess.run(['docker image prune -a'])

        return num_layers, inspect_output.stdout
    else:
        print(f"Failed to inspect the image: {image_name}")
        return None, None

def split_docker_image(image_name):
    if ":" in image_name:
        return image_name.split(":")[0]
    else:
        return image_name

print(df)
# Apply the custom function to the "docker image" column
df['docker image'] = df['docker image'].apply(split_docker_image)
df['dr img:tag'] = df['docker image'] + ":" +df['Tag ']
print(df)
# Create a new column to store the number of layers for each Docker image
df['Number of Layers'], df['Inspect Output'] = zip(*df['dr img:tag'].apply(perform_pull_inspect))

# Save the updated DataFrame to the Excel file
output_path = r''
df.to_excel(output_path, index=False)
