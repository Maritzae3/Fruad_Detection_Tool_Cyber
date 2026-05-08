// this file will hold the script for the dashboard.html page to show the charts
// the dashboard is readin tansaction data from the JSON file
// then it filters and visualizes suspicious data

// these arrays will hold our data
let allData = [];   // this holds all the transactions
let suspiciousData = [];  // this will hold only the flagged transactions


// "DOMContentLoaded" is a browser event, it waits until the HTML page finishes loading before running the code
//
// async () => means this function is asynchronus, it allows us to wait for things like loading files/data without freezing the webpage
document.addEventListener("DOMContentLoaded", async () => {

    try {  // try/catch for error handling (in case it fails to load), attempts to run the code
        const response = await fetch("../Data/all_results.json");  // fetch() is JS function to request a file or data , we are requesting the JSON file
    
        allData = await response.json();  // this pauses the function until we get the file/data we need


        // filter() creates a NEW array containing only items that match a condition
        // in this case we are looking for rows where the status == "Suspicious" to get the suspicous transactions
        suspiciousData = allData.filter(row => row.Status === "Suspicious");  // will gather the data labled as suspicious from the json file

        // now that we have the data, we call these functions to then build the charts to display
        buildStatusDonut(allData);
        buildFraudSignalChart(suspiciousData);
        buildRuleTriggerChart(suspiciousData);
        buildSeverityChart(suspiciousData);
        renderAlertTable(suspiciousData);

        enableChartCardFlips();

    } catch (error) {
        // in case of error, this prints the error message to the console which makes it easy for us to see where it happened
        console.error("Error loading dashboard data:", error);
    }
});

// adding the card fliping function to allow the cards to flip
function enableChartCardFlips() {
    const flipCards = document.querySelectorAll(".flip-card");

    flipCards.forEach(card => {
        card.addEventListener("click", () => {
            card.classList.toggle("is-flipped");
        });
    });
}

// this function takes the parameter "reason" text and turns it into an array
function parseReasons(reason) {
    if (!reason) return [];  // if there is no reason, then it is an empty array
    return reason
        .split(";")    // JSON files separate with ";" so the data is separated by that.
        .map(item => item.trim())  // loops through evert item in the array and trim() removes ectra space before/after text
        .filter(item => item.length > 0);  // removes empty items from array
}

// this function creates a risk score for each instance
// the higher the score == more suspicous
function getRiskScore(row) {

    const reasons = parseReasons(row.Reason);  // get all the suspicous reasons (we are getting transaction amount)
    const amount = Number(row["Transaction Amount"]) || 0;  // "Number" converts text into a number, if number is invalid then it is 0

    let score = 25 + reasons.length * 20;  // base score of 25

    if (amount >= 10000)   // super suspicous
        score += 20;
    else if (amount >= 5000) 
        score += 10;

    return Math.min(score, 100); 
}

//converts numeric score into severity lables
// ex: 90 --> critical
//     70 --> high
function getSeverity(score) {
    if (score >= 85) return "Critical";
    if (score >= 75) return "High";
    if (score >= 45) return "Medium";
    return "Low";
}

// converts detailed fraud reasons into simplified categories, this helps group similar fraud behaviors together for the charts
function mapReasonToSignal(reason) {
    const text = reason.toLowerCase();

    // checking whether the text includes certain key words to hint suspicion   
    if (text.includes("new country")) return "Geo Mismatch";
    if (text.includes("unknown devices")) return "Device Change";
    if (text.includes("failed login")) return "Account Access";
    if (text.includes("daily total")) return "Velocity";
    if (text.includes("large transfer")) return "Large Transfer";
    if (text.includes("structured")) return "Structuring";
    if (text.includes("same amount")) return "Repeated Amount";
    if (text.includes("unusual spending")) return "Unusual Spending";
    if (text.includes("over $10,000")) return "High Amount";

    return "Other";
}

// creates the donut chart for showing suspicious vs normal transactions
function buildStatusDonut(data) {
    // filter the suspicious rows and count them
    const suspiciousCount = data.filter(row => row.Status === "Suspicious").length;
    // filter normal rows and count them
    const normalCount = data.filter(row => row.Status === "Normal").length;

    // creates a Chart.js chart
    // document.getElementById() find the HTML canvas element by ID
    new Chart(document.getElementById("suspiciousTrend"), {
        type: "doughnut",  // type of chart
        data: {
        labels: ["Suspicious", "Normal"],  //lables to show in the chart
        datasets: [{
            data: [suspiciousCount, normalCount],
            backgroundColor: ["#dc2626", "#00D100"]
        }]
        },
        options: {
        responsive: true,  // responsive chart means it adjust to screen size
        maintainAspectRatio: false  // false allows custome height/width
        }
    });
}

// builds a bar chart showing fraud signal categories
function buildFraudSignalChart(data) {
    const signalCounts = {};  // object to count signals

    data.forEach(row => {  // forEach() loops thoug every item in an array
        const reasons = parseReasons(row.Reason);

        reasons.forEach(reason => {
        const signal = mapReasonToSignal(reason);
        signalCounts[signal] = (signalCounts[signal] || 0) + 1;  // if signl already exists, add 1
                                                                 // otherwise start at 0 and add 1
        });
    });

    // Object.keys() gets all object property names
    const labels = Object.keys(signalCounts);  
    // Object.values() get all object property values
    const values = Object.values(signalCounts);

    new Chart(document.getElementById("categoryChart"), {
        type: "bar",
        data: {
        labels: labels,
        datasets: [{
            label: "Signal Count",
            data: values,
            backgroundColor: "#2563eb"
        }]
        },
        options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
            display: true  // changed from false to true
            }
        },
        scales: {
            y: {
            beginAtZero: true   // chart starts at 0
            }
        }
        }
    });
}

// shows the most common fraud rules triggered
function buildRuleTriggerChart(data) {
    const ruleCounts = {};

    data.forEach(row => {
        const reasons = parseReasons(row.Reason);

        reasons.forEach(reason => {
        ruleCounts[reason] = (ruleCounts[reason] || 0) + 1;
        });
    });

    const sortedRules = Object.entries(ruleCounts)  // Object.entries() converts object into arrays
        .sort((a, b) => b[1] - a[1])  // sort the array by decending count order
        .slice(0, 6);  // slice keeping only the top 8 items (there is really only 5 items but just incase for a new data set)

    // map() transforms arrays into new arrays
    const labels = sortedRules.map(item => item[0]);
    const values = sortedRules.map(item => item[1]);

    new Chart(document.getElementById("ruleChart"), {
        type: "bar",
        data: {
        labels: labels,
        datasets: [{
            label: "Times Triggered",
            data: values,
            backgroundColor: "#2563eb"
        }]
        },
        options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
            display: false
            }
        },
        scales: {
            x: {  // horizontal chart
            beginAtZero: true
            }
        }
        }
    });
}

// creates chart for Critical/High?medium?low alerts
function buildSeverityChart(data) {
    // object storing the severity totals
    const severityCounts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0
    };

    data.forEach(row => {
        const score = getRiskScore(row);
        const severity = getSeverity(score);  // calling to the functions we have to get counts
        severityCounts[severity]++;
    });

    new Chart(document.getElementById("severityChart"), {
        type: "bar",
        data: {
        labels: Object.keys(severityCounts),
        datasets: [{
            label: "Alert Count",
            data: Object.values(severityCounts),
            backgroundColor: ["#dc2626", "#f59e0b", "#f97316", "#6b7280"]
        }]
        },
        options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
            display: false
            }
        },
        scales: {
            y: {
            beginAtZero: true
            }
        }
        }
    });
}

// creates the rows in the HTML table (to display the alerted transactions)
function renderAlertTable(data) {

    // this will find an HTML element using the CSS selector syntax
    const tableBody = document.querySelector("#alertTable tbody");
    tableBody.innerHTML = "";  // clears old table rows

    data.forEach(row => {
        const score = getRiskScore(row);
        const severity = getSeverity(score);

        // creates a new HTML element (row)
        const tr = document.createElement("tr");

        // format the table using the `` and allow inserting variables with ${} in the actual HTML table
        tr.innerHTML = `
        <td>${row["Transaction ID"] || ""}</td>
        <td>${row["Account ID"] || ""}</td>
        <td>$${Number(row["Transaction Amount"] || 0).toLocaleString()}</td>
        <td>${score}</td>
        <td><span class="severity-badge ${getSeverityClass(severity)}">${severity}</span></td>
        <td>${row.Location || ""}</td>
        <td>${formatDate(row["Time and Date"])}</td>
        <td>${row["Transaction Type"] || ""}</td>
        <td class="reason-cell">${row.Reason || ""}</td>
        `;

        // appendChild() adds the new row into the table
        tableBody.appendChild(tr);
    });
}

// return CSS class names based on severity, this lets CSS style the severity badges differently
function getSeverityClass(severity) {
    if (severity === "Critical") return "severity-critical";
    if (severity === "High") return "severity-high";
    if (severity === "Medium") return "severity-medium";
    return "severity-low";
}

// formats the rawdate text into readable local date/time
function formatDate(dateString) {
    // if no date exist, return blank
    if (!dateString) return "";
    // new Date() creates a JS date object
    // toLocalString() converts the date into readable format
    return new Date(dateString).toLocaleString();
}