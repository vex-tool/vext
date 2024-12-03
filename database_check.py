import sqlite3
import sys

def connect_db(database):
    conn = sqlite3.connect(database)
    conn.execute('PRAGMA journal_mode = WAL')
    return conn

def perform_sanity_checks(database):
    conn = connect_db(database)
    c = conn.cursor()

    # Check the count of records in the CVE table
    c.execute('SELECT COUNT(*) FROM cve')
    cve_count = c.fetchone()[0]
    print(f"Total CVEs in database: {cve_count}")

    # Check the count of records in the CWE table
    c.execute('SELECT COUNT(*) FROM cwe')
    cwe_count = c.fetchone()[0]
    print(f"Total CWEs in database: {cwe_count}")

    # Check for any CVE entries with no associated CWE
    c.execute('''
    SELECT COUNT(*) FROM cve_cwe
    WHERE cve_id NOT IN (SELECT id FROM cve)
    ''')
    invalid_cve_cwe_count = c.fetchone()[0]
    print(f"Invalid CVE-CWE mappings: {invalid_cve_cwe_count}")

    # Optional: Get a sample of CVEs
    # print("\nSample CVEs:")
    # c.execute('SELECT id FROM cve LIMIT 5')
    # for row in c.fetchall():
    #     print(f"CVE ID: {row[0]}")#, Description: {row[1]}")

    conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {__file__} <database_name>")
        sys.exit(1)

    database_name = sys.argv[1]
    perform_sanity_checks(database_name)

