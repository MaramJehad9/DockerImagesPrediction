import pandas as pd
import subprocess

# Run the docker image ls command and capture the output
docker_ls_cmd = "docker image ls"
output = subprocess.run(docker_ls_cmd, capture_output=True, text=True)

# Split the output into lines and skip the header
lines = output.stdout.strip().split('\n')[1:]

# Create lists to store the extracted information
repository = []
tag = []
image_id = []
created = []
size = []

# Parse the output and extract the information
for line in lines:
    parts = line.split()
    repository.append(parts[0])
    tag.append(parts[1])
    image_id.append(parts[2])
    created.append(parts[3] + " " + parts[4])
    size.append(parts[6])

# Create a pandas DataFrame with the extracted information
df = pd.DataFrame({
    'Repository': repository,
    'Tag': tag,
    'Image ID': image_id,
    'Created': created,
    'Size': size
})

# Save the DataFrame to an Excel file
output_path = r'docker_images_ls.xlsx'
df.to_excel(output_path, index=False)

print("Docker images list saved to Excel file:", output_path)
