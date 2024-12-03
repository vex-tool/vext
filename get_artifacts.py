import requests
import os
import zipfile
import io
import sys
from datetime import datetime

def download_and_extract(url, file_name, download_dir):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses

        # Create a BytesIO object from the response content
        with io.BytesIO(response.content) as zip_file:
            # Unzip the file
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(download_dir)
                print(f"Extracted files from {file_name} into {download_dir}")
    # Catch specific exceptions, and the general Exception to catch all others
    except requests.exceptions.RequestException as e:
        print(f"Failed to download {url}: {e}")
    except zipfile.BadZipFile:
        print(f"Failed to unzip the content for {url}: it may be corrupted.")
    except Exception as e:
        print(f"An error occurred: {e}")

def download_cve_files(start_year, stop_year, download_dir):
    for year in range(start_year, stop_year + 1):
        json_file_name = f"nvdcve-1.1-{year}.json"  # JSON file name after extraction
        json_file_path = os.path.join(download_dir, json_file_name)
        url = f"https://nvd.nist.gov/feeds/json/cve/1.1/{json_file_name}.zip"

        # Check if the JSON file already exists
        if os.path.exists(json_file_path):
            print(f"{json_file_name} already exists in {download_dir}.")
        else:
            download_and_extract(url, f"nvdcve-1.1-{year}.json.zip", download_dir)

def download_cwe_file(download_dir):
    cwe_url = "https://cwe.mitre.org/data/xml/views/1000.xml.zip"
    cwe_file_name = "1000.xml"
    cwe_file_path = os.path.join(download_dir, cwe_file_name)

    # Check if the CWE file has already been downloaded
    if os.path.exists(cwe_file_path):
        print(f"{cwe_file_name} already exists in {download_dir}.")
    else:
        download_and_extract(cwe_url, cwe_file_name, download_dir)

def get_artifacts(start_year, stop_year, data_directory):
    # Create the data directory if it doesn't exist
    os.makedirs(data_directory, exist_ok=True)

    print(f"Downloading artifacts from {start_year} to {stop_year} into {data_directory}...")

    # Download CVE files
    download_cve_files(start_year, stop_year, data_directory)

    # Download CWE file
    download_cwe_file(data_directory)

if __name__ == "__main__":
    start_year = int(sys.argv[1])  # Convert to int
    stop_year = int(sys.argv[2])    # Convert to int
    data_directory = sys.argv[3]
    get_artifacts(start_year, stop_year, data_directory)
