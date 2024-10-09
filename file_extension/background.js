chrome.downloads.onChanged.addListener(function(downloadDelta) {
    if (downloadDelta.state && downloadDelta.state.current === 'complete') {
        // Get the file details when the download completes
        chrome.downloads.search({ id: downloadDelta.id }, function(results) {
            if (results && results.length > 0) {
                const downloadUrl = results[0].url;  // Get the download URL
                scanDownloadedFile(downloadUrl);  // Pass the URL instead of the local file path
            }
        });
    }
});

function scanDownloadedFile(fileUrl) {
    const apiKey = "671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850";  // Replace with your VirusTotal API key
    console.log('---file URL---', fileUrl);
    
    fetch(`http://127.0.0.1:8000/adminapp/api/check_file/?file_url=${encodeURIComponent(fileUrl)}`, {
        method: 'POST',
        headers: {
            'x-apikey': apiKey
        }
    })
    .then(response => {
        console.log('---raw response---', response);  // Log the response to see what is coming from the API
        if (!response.ok) {
            throw new Error(`API call failed with status: ${response.status}`);
        }
        return response.json();  // Try parsing only if the status is OK
    })
    .then(data => {
        console.log('---result----', data, data.permalink);
        const scanResultLink = data.message;
        chrome.action.openPopup();  // Automatically open the popup
        console.log('---result2----', data);
        chrome.runtime.sendMessage({action: "scanResult", scanResult: scanResultLink});
        console.log('---result3----', data);
    })
    .catch(error => {
        console.log('Error scanning file:', error);
        chrome.runtime.sendMessage({action: "scanResult", scanResult: 'Error scanning file.'});
    });
}
