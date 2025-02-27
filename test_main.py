from mock_data import mock_data
from fastapi.testclient import TestClient
from main import app
from unittest.mock import patch

client = TestClient(app)


def test_get_records_no_filters():
    response = client.get("/cves")
    assert response.status_code == 200
    assert len(response.json()["records"]) == 10 # Should return both records
    assert response.json()["totalCount"] == 10  # Minimum count should be 10

def test_get_records_with_limit():
    response = client.get("/cves?limit=1")
    assert response.status_code == 200
    assert len(response.json()["records"]) == 1  # Only one record due to limit
    assert response.json()["totalCount"] == 1  # Total count should be 1

def test_get_records_with_cve_id_filter():
    response = client.get("/cves?cve_id=CVE-1999-0095")
    assert response.status_code == 200
    assert len(response.json()["records"]) == 1  # Should match one record
    assert response.json()["totalCount"] == 1  # Only 1 matching record

def test_get_records_with_year_filter():
    response = client.get("/cves?year=1988")
    assert response.status_code == 200
    assert len(response.json()["records"]) == 2  # Both records are from 1988
    assert response.json()["totalCount"] == 2  # Total count should be 2

def test_get_records_with_score_filter():
    response = client.get("/cves?cve_score=9.5")
    assert response.status_code == 200
    assert len(response.json()["records"]) == 10 # Both records have a score >= 9.5

def test_get_records_with_last_modified_days_filter():
    response = client.get("/cves?last_modified_days=30")
    assert response.status_code == 200
    assert len(response.json()["records"]) == 10  # Both records have been modified in the last 30 days
    assert response.json()["totalCount"] == 10  # Total count should be 2

def test_get_records_no_results():
    response = client.get("/cves?cve_id=CVE-9999-9999")
    assert response.status_code == 500  # No records should match this CVE ID
    assert response.json() == {"detail": "Internal Server Error"}

def test_sucessful_cve_detail():
    response = client.get("/cve-details?id=CVE-1999-0095")
    assert response.status_code == 200
    assert response.json()["cve_id"] == "CVE-1999-0095"
    assert response.json()["severity"] == "HIGH"
    assert response.json()["score"] == 10

def test_cve_details_not_found():
    response = client.get("/cve-details?id=CVE-9999-0000")
    assert response.status_code == 404

def test_cve_details_internal_server_error():
    response = client.get("/cve-details?id=CVE-2021-34527")
    assert response.status_code == 200