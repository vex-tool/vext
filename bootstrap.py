import json
import logging
import subprocess
import os

def run_script(script_name, *args):
    command = ["python", script_name] + list(args)
    logging.info("Running command: [%s]", " ".join(command))
    subprocess.run(command, check=True)


def main(config):
    start_year = config.get("start_year")
    stop_year = config.get("stop_year")
    db_name = config.get("db_name")
    data_directory = config.get("data_directory")
    cwe_file = config.get("cwe_file")
    log_file = config.get("log_file")

    # paths
    cwe_file_path = os.path.join(data_directory, cwe_file)
    db_path = os.path.join(data_directory, db_name)
    log_path = os.path.join(data_directory, log_file)

    # check for log directory first, and create it if it doesn't exist
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    # file and create it if it doesn't exist
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            f.write("")

    logging.basicConfig(
    filename=log_path,
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info("<<< Starting the bootstrap process...>>>")

    print("Grabbing artifacts...")
    run_script("get_artifacts.py", str(start_year), str(stop_year), data_directory)

    print("Starting the project...")
    run_script("database_setup.py", db_path)

    print("Setting up the CWEs...")
    run_script("database_cwe.py", db_path, cwe_file_path)

    print("Populating CVEs...")
    run_script("database_populate.py", db_path, data_directory)

    print("Performing sanity checks...")
    run_script("database_check.py", db_path)

    print("Done")
    logging.info("<<< Bootstrap process complete.>>>")


if __name__ == "__main__":
    with open("config.json") as f:
        config = json.load(f)
    main(config)
