import sqlite3
import logging
import sys

def create_database(db_name):
    # Connect to SQLite database (or create it)

    try:
        conn = sqlite3.connect(db_name)
        c = conn.cursor()

        # Create CVE table
        c.execute('''
        CREATE TABLE IF NOT EXISTS cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            published_date TEXT,
            last_modified_date TEXT,
            cvss_v2_score REAL,
            cvss_v3_score REAL,
            severity TEXT,
            impact TEXT
        )
        ''')

        # Create CWE table
        c.execute('''
        CREATE TABLE IF NOT EXISTS cwe (
            cwe_id TEXT PRIMARY KEY,
            description TEXT,
            name TEXT,
            abstraction TEXT,
            parent_cwe_id TEXT
        )
        ''')

        # Create CPE table
        c.execute('''
        CREATE TABLE IF NOT EXISTS cpe (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT,
            cpe_version TEXT,
            part TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            up_date TEXT,
            edition TEXT,
            language TEXT,
            sw_edition TEXT,
            target_sw TEXT,
            target_hw TEXT,
            other TEXT,
            UNIQUE (vendor, product, version)
        )
        ''')

        # Create CVE-CWE junction table
        c.execute('''
        CREATE TABLE IF NOT EXISTS cve_cwe (
            cve_id TEXT,
            cwe_id TEXT,
            PRIMARY KEY (cve_id, cwe_id),
            FOREIGN KEY (cve_id) REFERENCES cve(id),
            FOREIGN KEY (cwe_id) REFERENCES cwe(cwe_id)
        )
        ''')

        # Create CVE-CPE junction table
        c.execute('''
        CREATE TABLE IF NOT EXISTS cve_cpe (
            cve_id TEXT,
            cpe_id INTEGER,
            PRIMARY KEY (cve_id, cpe_id),
            FOREIGN KEY (cve_id) REFERENCES cve(id),
            FOREIGN KEY (cpe_id) REFERENCES cpe(id)
        )
        ''')


        # Commit changes
        conn.commit()
        print(f"Database '{db_name}' created successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred while creating the database: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    db_name = sys.argv[1] # if len(sys.argv) > 1 else 'cwe-cve.db'  # Default to 'cwe-cve.db' if no argument is provided
    create_database(db_name)
