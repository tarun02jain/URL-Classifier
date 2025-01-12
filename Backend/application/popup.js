document.addEventListener('DOMContentLoaded', () => {
  // Request the token from the background script
  chrome.runtime.sendMessage({ type: 'GET_TOKEN' }, (response) => {
    if (response.token) {
      // Get the URL of the current active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs[0].url;
        console.log('Current Tab URL:', url);

        // Make a POST request to the backend with the token
        fetch('http://127.0.0.1:5000/extract_features_and_predict/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${response.token}`,
          },
          body: JSON.stringify({ url: url }),
        })
          .then((response) => {
            if (!response.ok) {
              throw new Error('Network response was not ok');
            }
            return response.json();
          })
          .then((data) => {
            // Display the prediction result
            console.log(data);
            if (data.predictions == 1) {
              document.getElementById('result').textContent = 'Possibly Phished';
            } else {
              document.getElementById('result').textContent = 'Legit';
            }
          })
          .catch((error) => {
            console.error('There was a problem with the fetch operation:', error);
          });
      });
    } else {
      // If no token is found, prompt the user to log in
      console.error('No token found! Please log in.');
      document.getElementById('result').textContent = 'Please log in to use this extension.';
    }
  });
});
