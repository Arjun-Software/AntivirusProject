chrome.webNavigation.onCompleted.addListener(function (details) {
  chrome.tabs.get(details.tabId, function (tab) {
    if (tab.url) {
      sendUrlToAPI(tab.url);
    }
  });
});
console.log("98989")
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    const resultDiv = document.getElementById('result');
    console.log("^^^^^^^^");
    
    
    if (message.result && message.result.status === 'error') {
      resultDiv.textContent = 'Error: ' + message.result.message;
    } else {
      // Display whether the URL is clean or not
      if (message.result.is_clean) {
        resultDiv.textContent = 'The site is clean!';
      } else {
        resultDiv.textContent = 'The site may  yt be unsafe!';
      }
    }
});

  

  async function sendUrlToAPI(url) {
    console.log("-+-+-++-+")
    const apiUrl = `http://127.0.0.1:8000/adminapp/check_url/?url=${encodeURIComponent(url)}`;
    try {
        const response = await fetch(apiUrl);
        
        // Check if the response is okay (status code 200-299)
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        // Parse the JSON from the response
        const data = await response.json();
        console.log('Response type:', response.type);
        // Log the data to the console
        console.log("response.json()", response);
        console.log("today",data);
        chrome.runtime.sendMessage({ result: data});
    } catch (error) {
        console.error('There was a problem with the fetch operation:', error);
    }

    
     console.log("=-=-=-=-=--")
    fetch(apiUrl, {
      method: 'GET', // Assuming your Django endpoint expects a GET request.
    })
      .then(response => {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            console.log("-------ty---------",response)
          return response; // Parse JSON only if content-type is JSON
        } else {
          throw new Error('Received non-JSON response: ' + contentType);
        }
      })
      .then(data => {
        console.log("------yha tk---",data);
              
        chrome.runtime.sendMessage({ result: data });
      })
      .catch(error => {
        console.log('Error sending URL:', error.message);
        chrome.runtime.sendMessage({ result: { status: 'error', message: error.message } });
      });
  }


  