from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional
from db import cves
from datetime import datetime, timedelta, timezone
from models import Cpe, CveDetails
import logging

# Initialize FastAPI app
app = FastAPI()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Template and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


def format_date(date_str: Optional[str]) -> str:
    """Convert date from ISO format ('YYYY-MM-DDTHH:MM:SS.sss') to 'dd - mmm - YYYY'."""
    if not date_str:
        return "N/A"
    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
        return date_obj.strftime("%d - %b - %Y")  # Example: 01 - Jan - 2024
    except ValueError:
        return date_str  # Return original if parsing fails


def serialize_record(record: dict) -> dict:
    """Convert MongoDB document to a JSON serializable format."""
    record["_id"] = str(record["_id"])  # Convert ObjectId to string

    return {
        "CVE ID": record.get("CVE ID", "N/A"),
        "Published Date": format_date(record.get("Published Date")),
        "Score": record.get("Score", "N/A"),
        "Last Modified Date": format_date(record.get("Last Modified Date")),
        "Identifier": record.get("Identifier", "N/A"),
        "Status": record.get("Status", "N/A"),
    }


@app.get("/cve/list")
async def get_home(request: Request):
    records = cves.count_documents({})
    return templates.TemplateResponse("home.html", {"request": request, "records": records})


@app.get("/cves")
async def get_records(
    limit: int = Query(10, ge=1, description="The number of records to return, must be at least 1."),
    skip: int = Query(0, ge=0, description="The number of records to skip for pagination, must be 0 or more."),
    cve_id: Optional[str] = None,
    year: Optional[int] = None,
    cve_score: Optional[float] = None,
    last_modified_days: Optional[int] = None,
):
    """
    Fetch CVE records from the database with filters for CVE ID, year, CVE score, and modification date.

    - **limit**: Number of records to return (default 10).
    - **skip**: Number of records to skip (default 0).
    - **cve_id**: Optional filter by CVE ID (e.g., `CVE-2021-34527`)
    - **year**: Optional filter by publication year (4 digits YYYY format).
    - **cve_score**: Optional filter by CVE score (minimum value).
    - **last_modified_days**: Optional filter for records modified within the last N days. (int(days))

    Returns:
        - `records`: A list of matching CVE records.
        - `totalCount`: Total number of records that match the filters.

    Possible Errors:
        - `404 Not Found`: No records found.
        - `500 Internal Server Error`: Database error.
    """
    query = {}

    if cve_id:
        query["CVE ID"] = {"$regex": cve_id, "$options": "i"}

    if year:
        # Extract first 4 characters from "Publish Date" and compare it to the provided year
        query["$expr"] = {
            "$eq": [
                {"$toInt": {"$substr": ["$Published Date", 0, 4]}},  # Convert first 4 characters to integer
                year
            ]
        }

    if cve_score:
        query["Score"] = {"$gte": cve_score}

    if last_modified_days:
        # Calculate the threshold date (current date - N days)
        threshold_date = datetime.now(timezone.utc) - timedelta(days=last_modified_days)
        
        # Format threshold date to "YYYY-MM-DD" string (ignore time)
        threshold_date_str = threshold_date.strftime("%Y-%m-%d")
        print(f"Threshold Date (YYYY-MM-DD): {threshold_date_str}")  # Debugging

        # Match records where "Last Modified Date" is greater than or equal to the threshold date
        query["Last Modified Date"] = {"$gte": threshold_date_str}

    try:
        records = list(cves.find(query).skip(skip).limit(limit))
        total_count = len(records)

        if not records:
            raise HTTPException(status_code=404, detail="No records found")

    except Exception as e:
        logger.error(f"Database Query Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

    return {"records": [serialize_record(record) for record in records], "totalCount": total_count}


@app.get("/show-cve-details")
async def show_details(request: Request):
    return templates.TemplateResponse("cveDetails.html", {"request": request})


@app.get("/cve-details", response_model=CveDetails)
async def get_cve_details(id: str = Query(..., alias="id")):
    """
    Fetch CVE details from the database based on the CVE ID.

    This endpoint retrieves detailed information about a specific CVE 
    (Common Vulnerability and Exposure) based on the provided CVE ID.
    
    **Query Parameters:**
    - `id` (str): The CVE ID for which the details are to be fetched (e.g., `CVE-2021-34527`).
    
    **Response Model (`CveDetails`):**
    The response will contain detailed information about the CVE, including:
    - `cve_id`: The unique CVE identifier (e.g., `CVE-2021-34527`).
    - `description`: Description of the vulnerability.
    - `severity`: The severity level of the CVE (e.g., "HIGH", "LOW").
    - `score`: The CVE’s base score (Score out of 10).
    - `vector_string`: The attack vector string (e.g., "AV:L/AC:L/Au:N/C:C/I:C/A:C").
    - `access_vector`: The access vector for the vulnerability.(eg., "LOCAL)
    - `access_complexity`: The complexity of exploitation.
    - `authentication`: Whether authentication is required to exploit the vulnerability.
    - `confidentiality_impact`: The impact on confidentiality (e.g., "HIGH").
    - `integrity_impact`: The impact on integrity.
    - `availability_impact`: The impact on availability.
    - `exploitability_score`: The exploitability score of the CVE.
    - `impact_score`: The impact score of the CVE.
    - `cpe`: A list of Common Platform Enumerations (CPE) related to the CVE.

    **Error Handling:**
    - `404 Not Found`: If the CVE ID does not exist in the database.
    - `500 Internal Server Error`: If an error occurs while processing the request.

    **Example Request:**
    ```bash
    GET /cve-details?id=CVE-2021-34527
    ```

    **Example Response:**
    ```json
    {
        "cve_id": "CVE-2021-34527",
        "description": "Windows Print Spooler Remote Code Execution Vulnerability",
        "severity": "Critical",
        "score": 8.8,
        "vector_string": "NETWORK",
        "access_vector": "Network",
        "access_complexity": "Low",
        "authentication": "None",
        "confidentiality_impact": "High",
        "integrity_impact": "High",
        "availability_impact": "High",
        "exploitability_score": 10.0,
        "impact_score": 10.0,
        "cpe": [
            {
                "cpe_name": "cpe:/o:microsoft:windows_10:1909",
                "version_start_including": "10.0",
                "version_end_excluding": "10.1"
            }
        ]
    }
    ```

    **Possible Errors:**
    - `404 Not Found`: The requested CVE ID does not exist in the database.
    - `500 Internal Server Error`: An internal server error occurred while processing the request.
    """
    cve = cves.find_one({"CVE ID": id})

    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    try:
        cve_details = CveDetails(
            cve_id=cve.get("CVE ID", "N/A"),
            description=cve.get("Description", "N/A"),
            severity=cve.get("Severity", "N/A"),
            score=cve.get("Score", "N/A"),
            vector_string=cve.get("Vector String", "N/A"),
            access_vector=cve.get("Access Vector", "N/A"),
            access_complexity=cve.get("Access Complexity", "N/A"),
            authentication=cve.get("Authentication", "N/A"),
            confidentiality_impact=cve.get("Confidentiality Impact", "N/A"),
            integrity_impact=cve.get("Integrity Impact", "N/A"),
            availability_impact=cve.get("Availability Impact", "N/A"),
            exploitability_score=cve.get("Exploitability Score", "N/A"),
            impact_score=cve.get("Impact Score", "N/A"),
            cpe=[Cpe(**cpe) for cpe in cve.get("CPE", []) if isinstance(cpe, dict)],  # Ensure valid CPE objects
        )

        return cve_details

    except Exception as e:
        logger.error(f"Error processing CVE details: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing CVE details")
