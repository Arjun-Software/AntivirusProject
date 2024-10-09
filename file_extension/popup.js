
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "scanResult") {
        console.log("----------",request.scanResult);
        
        const scanResultLink = request.scanResult;
        // Display the scan result in the popup
        document.getElementById('result').textContent = scanResultLink;
        sendResponse({status: "Scan result received"});
    }
});

document.addEventListener('DOMContentLoaded', function () {
    chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
        if (request.action === "scanResult") {
            document.getElementById('result').innerText = request.scanResult;
        }
    });
});
