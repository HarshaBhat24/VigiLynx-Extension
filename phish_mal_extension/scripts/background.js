// background.js
const API_BASE_URL = 'http://localhost:5000/api';
const FETCH_TIMEOUT = 10000; // 10 seconds timeout

// Helper function to handle fetch with timeout
const fetchWithTimeout = (url, options = {}) => {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Request timed out')), FETCH_TIMEOUT)
    )
  ]);
};

// Initialize extension state on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ enabled: true });
  console.log('Extension installed with default state: enabled');
});

// Message handler for content script communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_ENABLED') {
    chrome.storage.local.get(['enabled'], (data) => {
      sendResponse({ enabled: data.enabled !== false }); // Default to true if undefined
    });
    return true; // Async response
  }

  if (request.type === 'CHECK_URL') {
    const url = request.url;
    console.log(`Checking URL: ${url}`);

    fetchWithTimeout(`${API_BASE_URL}/scan?input=${encodeURIComponent(url)}`)
      .then(response => {
        if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
        return response.json();
      })
      .then(data => {
        console.log('URL Scan Response:', data);
        const isMalware = data.vtStats && data.vtStats.malicious > 0;
        const isSuspicious = data.vtStats && data.vtStats.suspicious > 0;
        const isSafeOverall = data.isSafe && !isMalware;
        
        sendResponse({
          isSafe: isSafeOverall,
          isUnknown: !data.vtStats,
          isSuspicious: isSuspicious,
          message: data.geminiInsights || 'No additional insights available',
          vtStats: data.vtStats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 }
        });
      })
      .catch(error => {
        console.error('Error checking URL:', error);
        // Continue with a warning but don't block the user entirely on error
        sendResponse({ 
          isSafe: true, 
          isError: true,
          message: `Error checking URL: ${error.message}. Proceed with caution.` 
        });
      });

    return true; // Async response
  }
});

// File download monitoring
chrome.downloads.onChanged.addListener((downloadDelta) => {
  if (downloadDelta.state && downloadDelta.state.current === 'complete') {
    // Check if extension is enabled before scanning
    chrome.storage.local.get(['enabled'], (data) => {
      if (data.enabled === false) {
        console.log('Extension disabled, skipping file scan');
        return;
      }
      
      scanCompletedDownload(downloadDelta.id);
    });
  }
});

// Function to scan a completed download
function scanCompletedDownload(downloadId) {
  chrome.downloads.search({ id: downloadId }, (results) => {
    if (!results || results.length === 0) {
      console.error('Download item not found:', downloadId);
      return;
    }
    
    const downloadItem = results[0];
    const filePath = downloadItem.filename;
    const fileName = filePath.split(/[/\\]/).pop() || 'downloaded_file';

    if (!filePath) {
      console.error('No file path available for download:', downloadItem);
      return;
    }

    console.log(`Scanning downloaded file: ${fileName}`);
    
    // Show scanning notification
    chrome.notifications.create('scan-in-progress', {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Scanning Download',
      message: `Scanning ${fileName} for threats...`
    });

    // Fetch file content and send to API
    fetch(`file://${filePath}`)
      .then(response => response.blob())
      .then(blob => {
        const formData = new FormData();
        formData.append('file', blob, fileName);

        return fetchWithTimeout(`${API_BASE_URL}/scan-file`, {
          method: 'POST',
          body: formData
        });
      })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
        return response.json();
      })
      .then(data => {
        console.log('File scan results:', data);
        const isMalware = data.vtStats && data.vtStats.malicious > 0;
        const isSuspicious = data.vtStats && data.vtStats.suspicious > 0;
        const isSafeOverall = data.isSafe && !isMalware;

        if (!isSafeOverall) {
          chrome.notifications.create('scan-result', {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '⚠️ File Warning',
            message: `This file may be unsafe! ${isMalware ? 'Malware detected.' : 'Suspicious content detected.'}`
          });
        } else {
          chrome.notifications.create('scan-result', {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '✅ File Safe',
            message: 'This file appears to be safe.'
          });
        }
      })
      .catch(error => {
        console.error('Error scanning file:', error);
        chrome.notifications.create('scan-error', {
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: '⚠️ Scan Error',
          message: `Could not verify file safety: ${error.message}`
        });
      });
  });
}