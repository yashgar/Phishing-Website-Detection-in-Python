const recentChecks = [];

document.getElementById("urlForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    const url = document.getElementById("urlInput").value;
    const spinner = document.getElementById("loadingSpinner");
    const resultContainer = document.getElementById("resultContainer");

    spinner.style.display = "inline-block";
    resultContainer.innerHTML = "";

    try {
        const response = await fetch("/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        spinner.style.display = "none";

        let resultHTML = `
            <div class="alert ${data.result === "PHISHING" ? "alert-danger" : "alert-success"}">
                <h4>${data.result}</h4>
            </div>
        `;

        if (data.ssl_info && typeof data.ssl_info === "object") {
            resultHTML += `
                <div class="card mt-3">
                    <div class="card-body">
                        <h5 class="card-title text-primary">SSL Certificate Info</h5>
                        <table class="table table-sm">
                            <tbody>
                                <tr><th>Issued To</th><td>${data.ssl_info["Issued To"]}</td></tr>
                                <tr><th>Issued By</th><td>${data.ssl_info["Issued By"]}</td></tr>
                                <tr><th>Valid From</th><td>${data.ssl_info["Valid From"]}</td></tr>
                                <tr><th>Valid To</th><td>${data.ssl_info["Valid To"]}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } else {
            resultHTML += `<div class="alert alert-warning mt-2">No SSL certificate present</div>`;
        }

        resultContainer.innerHTML = resultHTML;
        recentChecks.unshift({
            url: url,
            result: data.result,
            ssl: (data.ssl_info && typeof data.ssl_info === "object") ? "Yes" : "No"
        });
        updateRecentChecksTable();

    } catch (error) {
        spinner.style.display = "none";
        resultContainer.innerHTML = `<div class="alert alert-danger">Error checking URL. Please try again.</div>`;
    }
});

function updateRecentChecksTable() {
    const tableBody = document.querySelector("#recentChecksTable tbody");
    tableBody.innerHTML = "";
    recentChecks.forEach((check, index) => {
        tableBody.innerHTML += `
            <tr>
                <td>${index + 1}</td>
                <td>${check.url}</td>
                <td><span class="badge ${check.result === "PHISHING" ? "bg-danger" : "bg-success"}">${check.result}</span></td>
                <td><span class="badge ${check.ssl === "Yes" ? "bg-info" : "bg-secondary"}">${check.ssl}</span></td>
            </tr>
        `;
    });
}