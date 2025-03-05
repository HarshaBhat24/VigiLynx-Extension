// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'GET_ENABLED') {
      chrome.storage.local.get(['enabled'], (data) => {
        sendResponse({ enabled: data.enabled !== false }); // Default to true if undefined
      });
      return true; // Async response
    }
  
    if (request.type === 'CHECK_URL') {
      const url = request.url;
  
      fetch(`http://localhost:5000/api/scan?input=${encodeURIComponent(url)}`)
        .then(response => {
          if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
          return response.json();
        })
        .then(data => {
          console.log('URL Scan Response:', data);
          const isMalware = data.vtStats && data.vtStats.malicious > 0;
          const isSafeOverall = data.isSafe && !isMalware;
          sendResponse({
            isSafe: isSafeOverall,
            message: data.geminiInsights,
            vtStats: data.vtStats
          });
        })
        .catch(error => {
          console.error('Error checking URL:', error);
          sendResponse({ isSafe: true, message: 'Error checking URL' });
        });
  
      return true; // Async response
    }
  });
  
  chrome.downloads.onChanged.addListener((downloadDelta) => {
    if (downloadDelta.state && downloadDelta.state.current === 'complete') {
      chrome.downloads.search({ id: downloadDelta.id }, (results) => {
        if (results && results.length > 0) {
          const downloadItem = results[0];
          const filePath = downloadItem.filename;
  
          if (!filePath) {
            console.error('No file path available for download:', downloadItem);
            return;
          }
  
          fetch(`file://${filePath}`)
            .then(response => response.blob())
            .then(blob => {
              const formData = new FormData();
              formData.append('file', blob, downloadItem.finalUrl.split('/').pop() || 'downloaded_file');
  
              return fetch('http://localhost:5000/api/scan-file', {
                method: 'POST',
                body: formData
              });
            })
            .then(response => {
              if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
              return response.json();
            })
            .then(data => {
              const isMalware = data.vtStats && data.vtStats.malicious > 0;
              const isSafeOverall = data.isSafe && !isMalware;
  
              if (!isSafeOverall) {
                chrome.notifications.create({
                  type: 'basic',
                  iconUrl: 'icons/icon48.png',
                  title: '⚠️ File Warning',
                  message: `This file is not safe! ${data.geminiInsights}`
                });
              } else {
                chrome.notifications.create({
                  type: 'basic',
                  iconUrl: 'icons/icon48.png',
                  title: '✅ File Safe',
                  message: 'This file is safe.'
                });
              }
            })
            .catch(error => {
              console.error('Error scanning file:', error);
              chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: '⚠️ Scan Error',
                message: 'Could not verify file safety.'
              });
            });
        }
      });
    }
  });