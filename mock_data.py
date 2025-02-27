"""Mock data for running unit tests on app"""

mock_data = [
    {
        "_id": "67bf92a7300326f75223e3d6",
        "CVE ID": "CVE-1999-0095",
        "Identifier": "cve@mitre.org",
        "Published Date": "1988-10-01T04:00:00.000",
        "Last Modified Date": "2024-11-20T23:27:50.607",
        "Status": "Modified",
        "Description": "The debug command in Sendmail is enabled...",
        "Severity": "HIGH",
        "Score": 10,
        "Vector String": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "Access Vector": "NETWORK",
        "Access Complexity": "LOW",
        "Authentication": "NONE",
        "Confidentiality Impact": "COMPLETE",
        "Integrity Impact": "COMPLETE",
        "Availability Impact": "COMPLETE",
        "Impact Score": 10,
        "Exploitability Score": 10,
        "CPE": [{"Object": "vulnerable", "criteria": "cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*"}]
    },
    {
        "_id": "67bf92a7300326f75223e3d7",
        "CVE ID": "CVE-1999-0082",
        "Identifier": "cve@mitre.org",
        "Published Date": "1988-11-11T05:00:00.000",
        "Last Modified Date": "2024-11-20T23:27:48.337",
        "Status": "Modified",
        "Description": "CWD ~root command in ftpd allows root access.",
        "Severity": "HIGH",
        "Score": 10,
        "Vector String": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "Access Vector": "NETWORK",
        "Access Complexity": "LOW",
        "Authentication": "NONE",
        "Confidentiality Impact": "COMPLETE",
        "Integrity Impact": "COMPLETE",
        "Availability Impact": "COMPLETE",
        "Impact Score": 10,
        "Exploitability Score": 10,
        "CPE": [{"Object": "vulnerable", "criteria": "cpe:2.3:a:ftp:ftp:*:*:*:*:*:*:*:*"}]
    }
]