let currentPage = 1;
let limit = 10;

document.getElementById("limit").addEventListener("change", function () {
  let newLimit = parseInt(this.value); // Get the selected limit value
  if (newLimit) {
    // Check if a valid limit is selected
    limit = newLimit; // Update the limit variable with the new value
  }
  currentPage = 1; // Reset to the first page
  fetchRecords(); // Fetch records with the new limit
});

async function fetchRecords() {
  let skip = (currentPage - 1) * limit;
  let cve_id = document.getElementById("cve_id").value;
  let year = document.getElementById("year").value;
  let cve_score = document.getElementById("cve_score").value;
  let last_modified_days = document.getElementById("last_modified_days").value;

  // Build query parameters
  let queryParams = new URLSearchParams({
    limit: limit,
    skip: skip,
  });

  if (cve_id) queryParams.append("cve_id", cve_id);
  if (year) queryParams.append("year", year);
  if (cve_score) queryParams.append("cve_score", cve_score);
  if (last_modified_days)
    queryParams.append("last_modified_days", last_modified_days);

  try {
    let response = await fetch(`/cves?${queryParams.toString()}`);
    let data = await response.json();

    if (response.ok) {
      renderRecords(data.records);
      document.getElementById("page-info").innerText = `Page ${currentPage}`;
    } else {
      document.getElementById(
        "records-table"
      ).innerHTML = `<tr><td colspan="4">${data.detail}</td></tr>`;
    }
  } catch (error) {
    console.error("Error fetching data:", error);
  }
}

function renderRecords(records) {
  let table = document.getElementById("records-table");
  table.innerHTML = ""; // Clear the table before adding new rows

  records.forEach((record) => {
    // Create a new row for each record
    let row = document.createElement("tr");

    // Set the onclick event on the row
    row.setAttribute(
      "onclick",
      `window.location.href='/show-cve-details?id=${record["CVE ID"]}'`
    );

    // Add data cells to the row
    row.innerHTML = `
          <td>${record["CVE ID"]}</td>
          <td>${record["Identifier"]}</td>
          <td>${record["Published Date"]}</td>
          <td>${record["Score"]}</td>
          <td>${record["Last Modified Date"]}</td>
          <td>${record["Status"]}</td>
      `;

    // Append the row to the table
    table.appendChild(row);
  });
}

function prevPage() {
  if (currentPage > 1) {
    currentPage--;
    fetchRecords();
  }
}

function nextPage() {
  currentPage++;
  fetchRecords();
}

document.addEventListener("DOMContentLoaded", fetchRecords);
