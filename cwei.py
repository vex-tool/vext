import os
import sqlite3
import logging
from pprint import pprint
import pandas as pd

# TODO read config file and include logging option in config

# Configure logging
logging.basicConfig(
    filename='cwei.log',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class CWEi:

    def __init__(self, db_path=None):
        """
        Initialize the CWEHierarchy object and load the CWE data from the database.

        :param db_path: Optional path to the SQLite database file. Defaults to './data/cwei.db'
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_db_path = os.path.join(base_dir, 'data', 'cwei.db')
        self.db_path = db_path or default_db_path

        logging.info("Initialized CWEi object with database path: %s", self.db_path)
        # self.db_path = db_path or './data/cwei.db'
        self.conn = self._connect_db()

        self.cwe_hierarchy = None
        self.reverse_lookup = None
        self._load_cwe_data()
        self.pillars = self._get_pillars()

    def _connect_db(self):
        conn = sqlite3.connect(self.db_path)
        return conn

    def _load_cwe_data(self):
        """Load CWE data from the database and build the hierarchy.
        
        The hierarchy is stored as a list of tuples where each CWE points to its parent CWE."""
        logging.info("Loading CWE data from the database.")
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT cwe_id, parent_cwe_id FROM cwe")
            self.cwe_data = c.fetchall()
            logging.info(f"Loaded {len(self.cwe_data)} CWEs from the database.")
            self.reverse_lookup = self._build_reverse_lookup(self.cwe_data)
        logging.info("CWE data loaded successfully.")

    def _get_pillars(self):
        """Get the top-level CWEs (pillars) from the hierarchy."""
        return [cwe_id for cwe_id, parent_id in self.cwe_data if parent_id is None]

    def _build_reverse_lookup(self, data):
        """
        Create a reverse lookup where each CWE points to its parent.

        :param data: List of tuples containing (cwe_id, parent_cwe_id)
        :return: Dictionary for reverse lookup
        """
        reverse_lookup = {}
        for cwe_id, parent_id in data:
            reverse_lookup[cwe_id] = parent_id
        return reverse_lookup

    def get_cwe_depth(self, cwe_id: str) -> int:
        """
        Get the depth of a CWE in the hierarchy.
        
        :param cwe_id: The CWE ID to calculate the depth for
        :return: Depth of the CWE from the root (0 means that it's a top-level CWE)
        """
        lookup_id = cwe_id
        depth = 0
        current_id = cwe_id
        while current_id in self.reverse_lookup and self.reverse_lookup[current_id] is not None:
            current_id = self.reverse_lookup[current_id]
            depth += 1
        logging.info(f"The depth of CWE-{lookup_id} is {depth}.")
        return depth

    def get_child_cwes(self, cwe_id: str, max_depth: int = 7) -> list[str]:
        """
        Get child CWEs of a given CWE up to a specified depth.
        
        :param cwe_id: The CWE ID to get the children for
        :param max_depth: Maximum depth of children to retrieve (default: 7)
        :return: List of child CWE IDs
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = f'''
                WITH RECURSIVE descendants(cwe_id, depth) AS (
                    SELECT cwe_id, 0
                    FROM cwe
                    WHERE cwe_id = ?

                    UNION ALL

                    SELECT c.cwe_id, d.depth + 1
                    FROM cwe c
                    INNER JOIN descendants d ON c.parent_cwe_id = d.cwe_id
                    WHERE d.depth < ?  -- Limit by max_depth
                )
                SELECT cwe_id
                FROM descendants
                WHERE cwe_id != ?;  -- Exclude the initial CWE ID
                '''
                cursor.execute(query, (cwe_id, max_depth, cwe_id))
                child_cwes = cursor.fetchall()
                if not child_cwes:
                    # logging.info(f"CWE-{cwe_id} has no child CWEs.")
                    return []
                else:
                    if max_depth != 7:
                    #     logging.info(f"CWE-{cwe_id} has {len(child_cwes)} child CWEs.")
                    # else:
                        logging.info(f"CWE-{cwe_id} has {len(child_cwes)} child CWEs up to depth {max_depth}")
                return [cwe[0] for cwe in child_cwes]
        except sqlite3.Error as e:
            logging.error(f"Database error while getting child CWEs for {cwe_id}: {e}")
            return []


    def get_cve_count_for_cwes(self, cwe_ids: list[str], year: str) -> dict[str, int]:
        """
        Get the count of associated CVEs for a set of CWEs in a specified year.

        :param cwe_ids: List of CWE IDs to get the CVE count for
        :param year: The year to filter the CVEs by
        :return: Dictionary of CWE IDs to their associated CVE counts
        """
        if not isinstance(cwe_ids, list) or not all(isinstance(id, str) for id in cwe_ids):
            raise ValueError("cwe_ids must be a list of strings.")
        if not isinstance(year, str) or len(year) != 4 or not year.isdigit():
            raise ValueError("year must be a string in YYYY format.")

        try:
            cve_counts = {}
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                placeholders = ', '.join('?' for _ in cwe_ids)
                query = f'''
                    SELECT cwe.cwe_id, COUNT(cve.id)
                    FROM cve
                    JOIN cve_cwe ON cve.id = cve_cwe.cve_id
                    JOIN cwe ON cwe.cwe_id = cve_cwe.cwe_id
                    WHERE cwe.cwe_id IN ({placeholders})
                    AND strftime('%Y', cve.published_date) = ?
                    GROUP BY cwe.cwe_id
                '''
                cursor.execute(query, (*cwe_ids, year))
                rows = cursor.fetchall()
                for cwe_id, count in rows:
                    # logging.info(f"CWE-{cwe_id} is associated with {count} CVEs in {year}.")
                    cve_counts[cwe_id] = count
            return cve_counts
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return {}

    def get_total_cve_count(self, cve_counts: list[str]) -> int:
        """
        Calculate total CVE count for a list of CWEs.

        :param cwe_ids: List of CWE IDs to calculate the total CVE count for
        :param year: The year to filter the CVEs by
        :return: Total CVE count for the given CWEs
        """
        # TODO consider using a lookup table to store the total CVE count for each year

        # cve_counts = self.get_cve_count_for_cwes(cwe_ids, year)
        # logging.info(f"Total CVE count for CWEs {cwe_ids[:1]}{len(cwe_ids)} in {year}: {sum(cve_counts.values())}")
        return sum(cve_counts.values())

    def get_vendors_for_cwe(self, cwe_id: str) -> list[str]:
        pass

    def get_cves(self, cwe_id: str) -> list[dict]:
        """
        Get the CVEs associated with a CWE in a lightweight format.
        Args:
            cwe_id (str): The CWE ID as a numeric string.
        Returns:
            List of dictionaries containing CVE information.
        """
        # Validate the input
        if not isinstance(cwe_id, str) or not cwe_id.isdigit():
            raise ValueError("cwe_id must be a numeric string.")

        try:
            cves = []

            # Connect to the database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Parameterized query to prevent SQL injection
                query = '''
                    SELECT cwe.cwe_id, cve.id, cve.description,
                    cve.severity, cve.cvss_v2_score, cve.cvss_v3_score,
                    cpe.part, cpe.vendor, cpe.product, cpe.version,
                    cpe.target_sw, cpe.target_hw,
                    cve.published_date, cve.last_modified_date
                    FROM cve
                    JOIN cve_cwe ON cve.id = cve_cwe.cve_id
                    JOIN cwe ON cwe.cwe_id = cve_cwe.cwe_id
                    JOIN cve_cpe ON cve.id = cve_cpe.cve_id
                    JOIN cpe ON cpe.id = cve_cpe.cpe_id
                    WHERE cwe.cwe_id = ?
                '''
                cursor.execute(query, (cwe_id,))
                columns = [column[0] for column in cursor.description]  # Get column names
                rows = cursor.fetchall()

                # Convert each row into a dictionary
                for row in rows:
                    cves.append(dict(zip(columns, row)))

                return cves

            return cves

        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return []    
    
if __name__ == "__main__":
    cwei = CWEi()
    pillars = cwei.get_pillars()
    print(f"Top-level CWEs: {pillars}")
