import json
import sqlite3
import sys
import os
from glob import glob

def connect_db(database):
    conn = sqlite3.connect(database)
    conn.execute('PRAGMA journal_mode = WAL')
    return conn

def insert_cve(conn, cve):
    c = conn.cursor()
    cve_id = cve['cve']['CVE_data_meta']['ID']
    description = cve['cve']['description']['description_data'][0]['value']
    published_date = cve['publishedDate']
    last_modified_date = cve['lastModifiedDate']
    cvss_v2_score = cve['impact'].get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
    cvss_v3_score = cve['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
    severity = cve['impact'].get('baseMetricV2', {}).get('severity')
    impact = json.dumps(cve['impact'])

    # Insert the CVE data
    c.execute('''
    INSERT OR IGNORE INTO cve (id, description, published_date, last_modified_date, cvss_v2_score, cvss_v3_score, severity, impact)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (cve_id, description, published_date, last_modified_date, cvss_v2_score, cvss_v3_score, severity, impact))

    # Insert CWEs and CPEs and link them
    insert_cwe_links(conn, cve_id, cve.get('cve', {}).get('problemtype', {}).get('problemtype_data', []))
    cpes = extract_cpe_data(cve)
    insert_cpe_links(conn, cve_id, cpes)

def insert_cwe_links(conn, cve_id, problem_types):
    c = conn.cursor()
    for problem in problem_types:
        for desc in problem.get('description', []):
            cwe_id = desc.get('value')

            # Trim the "CWE-" prefix
            if cwe_id and cwe_id.startswith("CWE-"):
                cwe_id = cwe_id[4:]

            if cwe_id:
                # Insert the CWE link into the cve_cwe table
                c.execute('''
                INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id)
                VALUES (?, ?)
                ''', (cve_id, cwe_id))

def extract_cpe_data(cve):
    cpe_list = []
    configurations = cve.get('configurations', {})
    if 'nodes' in configurations:
        for node in configurations['nodes']:
            for cpe_match in node.get('cpe_match', []):
                cpe23Uri = cpe_match.get('cpe23Uri')
                if cpe23Uri:
                    cpe_list.append(parse_cpe(cpe23Uri))
    return cpe_list

def parse_cpe(cpe_string):
    components = cpe_string.split(':')
    return {
        'prefix': components[0],
        'cpe_version': components[1],
        'part': components[2],
        'vendor': components[3],
        'product': components[4],
        'version': components[5] if len(components) > 5 else None,
        'update': components[6] if len(components) > 6 else None,
        'edition': components[7] if len(components) > 7 else None,
        'language': components[8] if len(components) > 8 else None,
        'sw_edition': components[9] if len(components) > 9 else None,
        'target_sw': components[10] if len(components) > 10 else None,
        'target_hw': components[11] if len(components) > 11 else None,
        'other': components[12] if len(components) > 12 else None
    }

def insert_cpe_links(conn, cve_id, cpe_list):
    '''Insert CPEs and link them to the CVE 
    We want to avoid inserting duplicate CPEs, so we use INSERT OR IGNORE
    Then to get the CPE ID, we use a subquery to get the ID of the CPE with the exact same values for all fields
    '''
    c = conn.cursor()
    for cpe in cpe_list:
        # Insert the CPE into the cpe table
        c.execute('''
        INSERT OR IGNORE INTO cpe (prefix, cpe_version, part, vendor, product, version, up_date, edition, language, sw_edition, target_sw, target_hw, other)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cpe['prefix'], cpe['cpe_version'], cpe['part'], cpe['vendor'], cpe['product'], cpe['version'], cpe['update'], cpe['edition'], cpe['language'], cpe['sw_edition'], cpe['target_sw'], cpe['target_hw'], cpe['other']))

        # Link the CVE to the CPE
        c.execute('''
        INSERT OR IGNORE INTO cve_cpe (cve_id, cpe_id)
        VALUES (?, 
                  (SELECT id FROM cpe WHERE prefix = ? AND cpe_version = ? AND part = ? AND vendor = ? AND product = ? AND version = ? AND up_date = ? AND edition = ? AND language = ? AND sw_edition = ? AND target_sw = ? AND target_hw = ? AND other = ?)
                  )
        ''', (cve_id, cpe['prefix'], cpe['cpe_version'], cpe['part'], cpe['vendor'], cpe['product'], cpe['version'], cpe['update'], cpe['edition'], cpe['language'], cpe['sw_edition'], cpe['target_sw'], cpe['target_hw'], cpe['other']))

def load_and_insert_cve_data(database_name, data_directory):
    conn = connect_db(database_name)
    # create_tables(conn)

    # Load JSON files and insert data
    for file_path in glob(os.path.join(data_directory, '*.json')):
        with open(file_path, 'r') as file:
            cve_data = json.load(file)
            for cve in cve_data['CVE_Items']:
                insert_cve(conn, cve)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python database_populate.py <database_name> <data_directory>")
        sys.exit(1)

    database_name = sys.argv[1]
    data_directory = sys.argv[2]
    load_and_insert_cve_data(database_name, data_directory)
