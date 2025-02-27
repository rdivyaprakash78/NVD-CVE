// Extract CVE ID from the URL
const cveId = new URLSearchParams(window.location.search).get("id");

// Fetch data from the FastAPI endpoint
fetch(`/cve-details?id=${cveId}`)
  .then((response) => response.json())
  .then((data) => {
    // Set the page title and CVE ID
    document.getElementById(
      "cve-title"
    ).textContent = `CVE Details - ${data.cve_id}`;
    document.getElementById("cve-id").textContent = `CVE - ${data.cve_id}`;

    // Description
    document.getElementById("description").textContent = data.description;

    // CVSS Metrics
    document.getElementById("severity").textContent = data.severity;
    document.getElementById("score").textContent = data.score;
    document.getElementById("vector-string").textContent = data.vector_string;

    // Impact Metrics
    document.getElementById("access-vector").textContent = data.access_vector;
    document.getElementById("access-complexity").textContent =
      data.access_complexity;
    document.getElementById("authentication").textContent = data.authentication;
    document.getElementById("confidentiality-impact").textContent =
      data.confidentiality_impact;
    document.getElementById("integrity-impact").textContent =
      data.integrity_impact;
    document.getElementById("availability-impact").textContent =
      data.availability_impact;

    // Score
    document.getElementById("exploitability-score").textContent =
      data.exploitability_score;
    document.getElementById("impact-score").textContent = data.impact_score;

    // CPE Table
    const cpeTableBody = document
      .getElementById("cpe-table")
      .getElementsByTagName("tbody")[0];
    data.cpe.forEach((cpe) => {
      const row = cpeTableBody.insertRow();
      row.innerHTML = `
        <td>${cpe.criteria}</td>
        <td>${cpe.matchCriteriaId}</td>
        <td>${cpe.vulnerable ? "Yes" : "No"}</td>
      `;
    });
  })
  .catch((error) => {
    console.error("Error fetching CVE details:", error);
  });
