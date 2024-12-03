import os
import json
import random
from glob import glob

def load_and_sample_cve_data(data_directory):
    # Load all available CVE data files
    json_files = glob(os.path.join(data_directory, 'nvdcve-1.1-*.json'))

    if not json_files:
        print(f"No CVE data files found in the {data_directory} directory.")
        return  # Exit if no files found

    cve_by_year = {}

    for file_path in json_files:
        print(f"Loading {file_path}")
        try:
            with open(file_path) as f:
                data = json.load(f)
            print(f"Found {len(data['CVE_Items'])} CVEs in {file_path}.")  # Debug info
            for cve in data['CVE_Items']:
                year = cve['publishedDate'][:4]  # Extract the year
                if year not in cve_by_year:
                    cve_by_year[year] = []
                cve_by_year[year].append(cve)
        except FileNotFoundError:
            print(f"No data file found at {file_path}")
        except json.JSONDecodeError:
            print(f"Error decoding JSON from file: {file_path}")
        except Exception as e:
            print(f"An error occurred while processing {file_path}: {e}")

    # Create a directory for output files if it doesn't exist
    output_dir = 'samples'
    os.makedirs(output_dir, exist_ok=True)

    # Randomly select one CVE per year and write to separate JSON files
    for year, cves in cve_by_year.items():
        if cves:  # Ensure there are CVEs for the year
            selected_cve = random.choice(cves)
            output_file = os.path.join(output_dir, f'CVE_{selected_cve["cve"]["CVE_data_meta"]["ID"]}_{year}.json')
            with open(output_file, 'w') as f:
                json.dump(selected_cve, f, indent=4)
            print(f"Wrote CVE to {output_file}")

# Example usage:
load_and_sample_cve_data('./data')  # Adjust the data_directory as needed
