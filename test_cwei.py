import unittest
import sqlite3
import os

from cwei import CWEi


class TestCWEi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Create a test database and populate it with sample data."""
        cls.db_path = "test_cwe_cve.db"
        cls.create_test_database(cls.db_path)
        cls.cwei = CWEi(db_path=cls.db_path)

    @classmethod
    def tearDownClass(cls):
        """Remove the test database after tests."""
        os.remove(cls.db_path)

    @staticmethod
    def create_test_database(db_name):
        """Create a test SQLite database with sample data."""
        conn = sqlite3.connect(db_name)
        c = conn.cursor()

        # Create sample CWEs (from Pillar 707 to Variant 82)
        c.execute(
            """
        CREATE TABLE cwe (
            cwe_id TEXT PRIMARY KEY,
            description TEXT,
            name TEXT,
            abstraction TEXT,
            parent_cwe_id TEXT
        )"""
        )
        c.execute(
            """INSERT OR IGNORE INTO cwe (cwe_id, description, name, abstraction, parent_cwe_id)
        VALUES ('707',
        'If a message is malformed, it may cause the message to be incorrectly interpreted. Neutralization is an abstract term for any technique that ensures that input (and output) conforms with expectations and is "safe."  This can be done by: This weakness typically applies in cases where the product prepares a control message that another process must act on, such as a command or query, and malicious input that was intended as data, can enter the control plane instead. However, this weakness also applies to more general cases where there are not always control implications.',
        'Improper Neutralization',
        'Pillar',
        'None')"""
        )

        c.execute(
            """INSERT OR IGNORE INTO cwe (cwe_id, description, name, abstraction, parent_cwe_id)
        VALUES ('74',
        "Description not available",
        "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
        'Class',
        '707')"""
        )
        c.execute(
            """INSERT OR IGNORE INTO cwe (cwe_id, description, name, abstraction, parent_cwe_id)
        VALUES (
        '79',
        'Cross-site scripting (XSS) vulnerabilities occur when...',
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        'Base',
        '74')"""
        )

        c.execute(
            """INSERT OR IGNORE INTO cwe (cwe_id, description, name, abstraction, parent_cwe_id)
        VALUES ('82', 'Description not available', 'Improper Neutralization of Script in Attributes of IMG Tags in a Web Page', 'Variant', '83')"""
        )

        c.execute(
            """INSERT OR IGNORE INTO cwe (cwe_id, description, name, abstraction, parent_cwe_id)
        VALUES ('83', '----', 'Improper Neutralization of Script in Attributes in a Web Page', 'Variant', '79')"""
        )

        # Create sample CVEs
        c.execute(
            """
        CREATE TABLE cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            published_date TEXT,
            last_modified_date TEXT,
            cvss_v2_score REAL,
            cvss_v3_score REAL,
            severity TEXT,
            impact TEXT
        )"""
        )
        c.execute(
            """INSERT INTO "cve" VALUES ('CVE-2023-7293',
            'The Paytium: Mollie payment forms & donations plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability 
            check on the check_mollie_account_details function in versions up to, and including, 4.3.7. This makes it possible for authenticated attackers 
            with subscriber-level access to verify the existence of a mollie account.',
            '2024-10-16T07:15Z',
            '2024-10-17T17:33Z',
            NULL,4.3,NULL,'{"baseMetricV3": {"cvssV3": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "NONE", "availabilityImpact": "NONE", "baseScore": 4.3, "baseSeverity": "MEDIUM"}, "exploitabilityScore": 2.8, "impactScore": 1.4}}');"""
        )
        c.execute(
            """INSERT INTO cve (id, description, published_date) 
            VALUES ('CVE-2023-12346', 'Another CVE description', '2023-02-01')"""
        )

        # Create CVE-CWE junction
        c.execute(
            """
        CREATE TABLE cve_cwe (
            cve_id TEXT,
            cwe_id TEXT,
            FOREIGN KEY (cve_id) REFERENCES cve(id),
            FOREIGN KEY (cwe_id) REFERENCES cwe(cwe_id),
            PRIMARY KEY (cve_id, cwe_id)
        )"""
        )
        c.execute(
            """INSERT INTO cve_cwe (cve_id, cwe_id) 
            VALUES ('CVE-2023-7293', '74')"""
        )
        c.execute(
            """INSERT INTO cve_cwe (cve_id, cwe_id)
            VALUES ('CVE-2023-12346', '79')"""
        )

        conn.commit()
        conn.close()

    def test_get_cwe_depth(self):
        self.assertEqual(self.cwei.get_cwe_depth("82"), 5)
        self.assertEqual(self.cwei.get_cwe_depth("1000"), 0)
        self.assertEqual(self.cwei.get_cwe_depth("707"), 1)
        self.assertEqual(self.cwei.get_cwe_depth("74"), 2)
        self.assertEqual(self.cwei.get_cwe_depth("79"), 3)
        self.assertEqual(self.cwei.get_cwe_depth("83"), 4)

    def test_get_child_cwes(self):
        children = self.cwei.get_child_cwes("74")
        self.assertIn("79", children)

    def test_get_cve_count_for_cwes_23(self):
        cve_counts = self.cwei.get_cve_count_for_cwes(["74", "79"], "2023")
        self.assertEqual(cve_counts["79"], 1)

    def test_get_cve_count_for_cwes_24(self):
        cve_counts = self.cwei.get_cve_count_for_cwes(["74", "79"], "2024")
        self.assertEqual(cve_counts["74"], 1)

    def test_get_total_cve_count(self):
        cve_counts = self.cwei.get_cve_count_for_cwes(["74", "79"], "2023")
        total_count = self.cwei.get_total_cve_count(cve_counts)
        self.assertEqual(total_count, 1)


if __name__ == "__main__":
    unittest.main()
