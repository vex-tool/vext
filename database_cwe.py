import xml.etree.ElementTree as ET
import sqlite3
import sys
from pprint import pprint
import logging


def connect_db(database):
    conn = sqlite3.connect(database)
    return conn


def insert_cwe_data(conn, cwe_data):
    c = conn.cursor()
    for cwe in cwe_data:
        cwe_id = cwe["CWE_ID"]
        name = cwe["Name"]
        description = cwe["Description"] or "Description not available"
        abstraction = cwe["Type"]

        # Use Primary_Parent_CWE_ID, with a fallback to None
        parent_cwe_id = cwe.get("Primary_Parent_CWE_ID", None)

        query = """
        INSERT OR IGNORE INTO cwe (cwe_id, description, name, abstraction, parent_cwe_id)
        VALUES (?, ?, ?, ?, ?)
        """
        params = (cwe_id, description, name, abstraction, parent_cwe_id)

        # Insert CWE into the database
        c.execute(query, params)

        # if cwe_id in ["82","83","79","74","707"]:
        #     # print("Executing query:", query)
        #     # print("With parameters:", params)
        #     parsed_query = query.replace("?", "'{}'").format(*params)
        #     print("Parsed SQL statement:", parsed_query)

    conn.commit()


def parse_cwe_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return []

    namespace = {
        "cwe": "http://cwe.mitre.org/cwe-7",
        "xhtml": "http://www.w3.org/1999/xhtml",
    }
    cwe_data = []

    for weakness in root.findall(".//cwe:Weakness", namespaces=namespace):
        cwe_id = weakness.attrib.get("ID")
        name = weakness.attrib.get("Name")
        abstraction = weakness.attrib.get("Abstraction")

        # Initialize variables for description and parent CWE IDs
        description_text = "----"
        primary_parent_cwe_id = None

        # Get the description
        description_elem = weakness.find(
            "cwe:Extended_Description", namespaces=namespace
        )
        if description_elem is not None:
            paragraphs = description_elem.findall(".//xhtml:p", namespaces=namespace)
            description_text = "\n".join(p.text for p in paragraphs if p.text)

        # Process related weaknesses
        related_weaknesses = weakness.find(
            "cwe:Related_Weaknesses", namespaces=namespace
        )
        if related_weaknesses is not None:
            for related in related_weaknesses.findall(
                "cwe:Related_Weakness", namespaces=namespace
            ):
                if (
                    (related.attrib.get("Nature") == "ChildOf")
                    and (related.attrib.get("Ordinal") == "Primary")
                    and (related.attrib.get("View_ID") == "1000")
                ):
                    parent_id = related.attrib.get("CWE_ID")
                    primary_parent_cwe_id = parent_id
                # parent_id = related.attrib.get('CWE_ID')
                # if related.attrib.get('Ordinal') == 'Primary':
                #     primary_parent_cwe_id = parent_id

        # Append CWE data
        cwe_data.append(
            {
                "CWE_ID": cwe_id,
                "Name": name,
                "Description": description_text,
                "Type": abstraction,
                "Primary_Parent_CWE_ID": primary_parent_cwe_id,
            }
        )
        logging.info(
            f"Processed CWE-{cwe_id}: {name}: primary_parent_cwe_id={primary_parent_cwe_id}"
        )

    return cwe_data


def main(database_name, xml_file):
    conn = connect_db(database_name)

    cwe_data = parse_cwe_xml(xml_file)
    logging.info("Got", len(cwe_data), "records")
    if cwe_data:
        insert_cwe_data(conn, cwe_data)
    else:
        print("No CWE data extracted.")

    conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python database_cwe.py <database_name> <cwe_file>")
        sys.exit(1)

    database_name = sys.argv[1]
    xml_file = sys.argv[2]
    main(database_name, xml_file)
