// Listen for messages from background.js
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  const resultDiv = document.getElementById('result');
console.log(";==='''",resultDiv);

  if (message.result && message.result.status === 'error') {
    resultDiv.textContent = 'Error: ' + message.result.message;
  } else {
    console.log('=======================',message.result);
    
    // Display whether the URL is clean or not
    if (message.result.is_clean) {
      resultDiv.textContent = 'The site is clean!';
    } else {
      resultDiv.textContent = 'The site may be unsafe hai!';
    }
  }
});
