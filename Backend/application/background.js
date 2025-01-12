chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'STORE_TOKEN') {
    // Store the token in chrome.storage.local
    chrome.storage.local.set({ authToken: message.token }, () => {
      console.log('Token stored successfully.');
      sendResponse({ success: true });
    });
    return true; // Indicates asynchronous response
  }

  if (message.type === 'GET_TOKEN') {
    // Retrieve the token from chrome.storage.local
    chrome.storage.local.get('authToken', (result) => {
      sendResponse({ token: result.authToken });
    });
    return true; // Indicates asynchronous response
  }
});
