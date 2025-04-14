import subprocess
import pandas as pd

def perform_docker_search(image_name):
    command = f"docker search {image_name}"
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError:
        return "Error"


df = pd.read_excel(r"/path/to/your/excel_file_from pull_cmd.py")
# Add a new column to the DataFrame to store search results
df['Search Results'] = df['Docker Name'].apply(perform_docker_search)

df.to_excel("dataset_with_search_img.xlsx")
