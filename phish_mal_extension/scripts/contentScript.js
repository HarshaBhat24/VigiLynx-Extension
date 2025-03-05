// contentScript.js
document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (link) {
      const url = link.href;
  
      if (!url || url.startsWith('javascript:')) {
        console.log('Skipping invalid URL:', url);
        return;
      }
  
      e.preventDefault(); // Block navigation
      console.log('Link clicked:', url);
  
      // Send message to background script to check 'enabled' state
      chrome.runtime.sendMessage({ type: 'GET_ENABLED' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error communicating with background:', chrome.runtime.lastError);
          alert('⚠️ Error checking extension state. Proceeding with caution.');
          window.location.href = url; // Fallback behavior
          return;
        }
  
        if (response && response.enabled === false) {
          window.location.href = url; // Proceed if extension is disabled
          return;
        }
  
        chrome.runtime.sendMessage({ type: 'CHECK_URL', url }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('Error:', chrome.runtime.lastError);
            alert('⚠️ Error checking URL. Proceed with caution.');
            return;
          }
  
          if (response) {
            if (response.isSafe) {
              alert('✅ This URL is safe you may proceed to the website.');
              window.location.href = url; // Allow navigation only if safe
            } else {
              alert(`⚠️ Not safe! ${response.message}`);
              // No redirection for unsafe URLs
            }
          }
        });
      });
    }
  });