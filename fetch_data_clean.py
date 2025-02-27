import requests
import time
import pandas as pd
import schedule
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from db import cves

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_ITEMS_PER_REQUEST = 2000

def insert_into_db(formatted_data):
    cve_id = formatted_data.get("CVE ID", None)

    if cve_id:
        existing_cve = cves.find_one({"CVE ID": cve_id})

        if existing_cve:
            print(f"CVE ID {cve_id} already exists in the database. Skipping insertion.")
        else:
            # Insert the new CVE data into the collection
            cves.insert_one(formatted_data)

def format_response_and_insert_to_db(data):
    """This function takes the raw response from the API and converts it
    into a suitable format for the application"""
    
    organized_data = []
    
    if data:
        vulnerabilities = data.get("vulnerabilities", [])
    else:
        return organized_data
        
    for vulnerability in vulnerabilities:
        
        cve = vulnerability.get("cve", {})

        # page 1 features
        cve_id = cve.get("id", "")
        identifier = cve.get("sourceIdentifier", "")
        published_date = cve.get("published", "")
        last_modified_date = cve.get("lastModified", "")
        status = cve.get("vulnStatus", "")

        # Page 2 features
        description_list = cve.get("descriptions", None)
        description = ""
        
        if description_list:
            description = "\n".join([element["value"] for element in description_list])
        
        cvss_metrics = cve.get("metrics", {}).get("cvssMetricV2", [])
        
        if cvss_metrics:
            severity = cvss_metrics[0].get("baseSeverity", "")
            impact_score = cvss_metrics[0].get("impactScore", "")
            exploitability_score = cvss_metrics[0].get("exploitabilityScore", "")
            score = cvss_metrics[0].get("cvssData", {}).get("baseScore", "")
            vector_string = cvss_metrics[0].get("cvssData", {}).get("vectorString", "")
            access_vector = cvss_metrics[0].get("cvssData", {}).get("accessVector","")
            access_complexity = cvss_metrics[0].get("cvssData", {}).get("accessComplexity","")
            authentication = cvss_metrics[0].get("cvssData", {}).get("authentication","")
            confidentiality_impact = cvss_metrics[0].get("cvssData", {}).get("confidentialityImpact","")
            integrity_impact = cvss_metrics[0].get("cvssData", {}).get("integrityImpact","")
            availability_impact = cvss_metrics[0].get("cvssData", {}).get("availabilityImpact","")
        
        cpe_list = cve.get("configurations", None)
        cpe_rows = []
        
        if cpe_list:
            node_list = cpe_list[0].get("nodes", None)
            if node_list:
                cpe_rows = node_list[0].get("cpeMatch", [])

        cve_id = cve_id if 'cve_id' in locals() else None
        identifier = identifier if 'identifier' in locals() else None
        published_date = published_date if 'published_date' in locals() else None
        last_modified_date = last_modified_date if 'last_modified_date' in locals() else None
        status = status if 'status' in locals() else None
        description = description if 'description' in locals() else None
        severity = severity if 'severity' in locals() else None
        score = score if 'score' in locals() else None
        vector_string = vector_string if 'vector_string' in locals() else None
        access_vector = access_vector if 'access_vector' in locals() else None
        access_complexity = access_complexity if 'access_complexity' in locals() else None
        authentication = authentication if 'authentication' in locals() else None
        confidentiality_impact = confidentiality_impact if 'confidentiality_impact' in locals() else None
        integrity_impact = integrity_impact if 'integrity_impact' in locals() else None
        availability_impact = availability_impact if 'availability_impact' in locals() else None
        impact_score = impact_score if 'impact_score' in locals() else None
        exploitability_score = exploitability_score if 'exploitability_score' in locals() else None
        cpe_rows = cpe_rows if 'cpe_rows' in locals() else None
        
        formatted_data = {
            "CVE ID": cve_id,
            "Identifier": identifier,
            "Published Date": published_date,
            "Last Modified Date": last_modified_date,
            "Status": status,
            "Description": description,
            "Severity": severity,
            "Score": score,
            "Vector String": vector_string,
            "Access Vector": access_vector,
            "Access Complexity": access_complexity,
            "Authentication": authentication,
            "Confidentiality Impact": confidentiality_impact,
            "Integrity Impact": integrity_impact,
            "Availability Impact": availability_impact,
            "Impact Score": impact_score,
            "Exploitability Score": exploitability_score,
            "CPE": cpe_rows
        }
        
        insert_into_db(formatted_data)
    
    return None

def make_request(offset, limit):
    URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={offset}&resultsPerPage={limit}"
    
    try:
        response = requests.get(URL)
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.HTTPError as err:
        if response.status_code == 503 or response.status_code == 403:
            print("Error 503: Service Unavailable. Retrying in 30 seconds...")
            time.sleep(30)  # Wait for 30 seconds before retrying
            return make_request(offset, limit)  # Retry the request
        else:
            print(f"HTTP Error occurred: {err}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
    return None  # Return None if there was an error

def fetch_data():
    total_results = None 
    offset = 0
    limit = 2000
    
    while total_results is None or offset < total_results:
        data = make_request(offset, limit)
        
        if total_results is None and data:
            total_results = data.get("totalResults", 0)
        
        format_response_and_insert_to_db(data)
        
        offset += limit
        
        print(f"Fetched {offset}/{total_results} results...")
        time.sleep(1) 
    
    return None


# Periodic fetch task using schedule
def periodic_task():
    print("Fetching new CVE data...")
    fetch_data()  # Fetch and insert data into MongoDB
    print("Finished fetching CVE data.")

"""
# Schedule periodic execution every hour
schedule.every(10).seconds.do(periodic_task)

# Keep the script running to handle scheduled tasks
while True:
    schedule.run_pending()
    time.sleep(60)  # Sleep for 1 minute before checking again

    """

fetch_data()  # Fetch and insert data into MongoDB when the script is run directly
