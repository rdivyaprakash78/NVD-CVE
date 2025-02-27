# CVE API Setup Guide

## 1. Create a Virtual Environment

Before installing dependencies, create and activate a virtual environment:

```sh
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

## 2. Setup MongoDB

Ensure MongoDB is installed and running on your system. You can start MongoDB using:

```sh
# Start MongoDB service (for local setup)
mongod --dbpath <your-db-path>
```

Alternatively, you can use a cloud-based MongoDB service like MongoDB Atlas.

## 3. Create a `.env` File

Create a `.env` file in the project root to store database credentials and the NIST API URL:

```
DB_USERNAME=<your-db-username>
DB_PASSWORD=<your-db-password>
NIST_API_URL=<nist-api-url>
```

## 4. Install Dependencies

Install the required dependencies using:

```sh
pip install -r requirements.txt
```

## 5. Brief API Overview

### `/cves` - Get CVE Records
This endpoint fetches CVE records with optional filters like:
- **CVE ID** (specific vulnerability ID)
- **Year** (publication year)
- **CVE Score** (minimum severity score)
- **Last Modified Days** (records modified within N days)

### `/cve-details` - Get CVE Details
This endpoint retrieves detailed information about a specific CVE, including:
- **Description** of the vulnerability
- **Severity level** and **CVE Score**
- **Exploitability & Impact Scores**
- **Affected platforms (CPEs)**

These endpoints help retrieve and analyze cybersecurity vulnerabilities efficiently.
