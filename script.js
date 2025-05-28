function startScan() {
    fetch("http://localhost:5000/start-full-scan")
        .then(response => response.json())
        .then(data => {
            console.log(data.status);
            checkScanStatus();  // Start checking scan status
        });
}

function stopScan() {
    fetch("http://localhost:5000/stop-scan")
        .then(response => response.json())
        .then(data => {
            console.log(data.status);
            alert("Scan Stopped!");  // Show popup immediately
        });
}

function checkScanStatus() {
    let interval = setInterval(() => {
        fetch("http://localhost:5000/scan-status")
            .then(response => response.json())
            .then(data => {
                if (!data.scan_running) {
                    clearInterval(interval);
                    alert("Scan Completed or Stopped!");  // Popup when scan stops
                }
            });
    }, 2000); // Check every 2 seconds
}
