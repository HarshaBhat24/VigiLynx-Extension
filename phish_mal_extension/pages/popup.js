// popup.js
document.addEventListener('DOMContentLoaded', function() {
  const statusText = document.getElementById('status');
  const toggleSwitch = document.getElementById('toggleSwitch');
  const serverStatusElement = document.getElementById('serverStatus');
  
  // Initialize toggle state from storage
  chrome.storage.local.get(['enabled'], (data) => {
    const enabled = data.enabled !== false; // Default to true if undefined
    toggleSwitch.checked = enabled;
    updateStatus(enabled);
  });
  
  // Toggle extension state
  toggleSwitch.addEventListener('change', function() {
    const enabled = this.checked;
    chrome.storage.local.set({ enabled });
    updateStatus(enabled);
  });
  
  // Update status display
  function updateStatus(enabled) {
    statusText.textContent = `Extension is ${enabled ? 'active' : 'disabled'}.`;
    statusText.className = enabled 
      ? 'text-center text-sm text-green-600 font-medium mb-2'
      : 'text-center text-sm text-gray-500 mb-2';
  }
  
  // Check server status
  checkServerStatus();
  
  // Set up periodic server status check
  setInterval(checkServerStatus, 30000); // Check every 30 seconds
  
  // Function to check server status
  function checkServerStatus() {
    serverStatusElement.innerHTML = '<span class="status-indicator pulse"></span> Checking...';
    
    // Add a timeout to handle cases where the server is completely down
    const timeout = setTimeout(() => {
      serverStatusElement.innerHTML = '<span class="status-indicator status-error"></span> Offline';
      serverStatusElement.classList.add('text-red-500');
    }, 5000);
    
    fetch('http://localhost:5000/api/status', { 
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      mode: 'cors'
    })
    .then(response => {
      clearTimeout(timeout);
      if (response.ok) {
        return response.json();
      } else {
        throw new Error(`Server responded with status: ${response.status}`);
      }
    })
    .then(data => {
      serverStatusElement.innerHTML = '<span class="status-indicator status-active"></span> Online';
      serverStatusElement.classList.remove('text-red-500');
      serverStatusElement.classList.add('text-green-500');
    })
    .catch(error => {
      clearTimeout(timeout);
      console.error('Server status check failed:', error);
      
      // Still try a basic ping to the server root as fallback
      fetch('http://localhost:5000/', { mode: 'no-cors' })
        .then(() => {
          serverStatusElement.innerHTML = '<span class="status-indicator status-active"></span> Online (Limited)';
          serverStatusElement.classList.remove('text-red-500');
          serverStatusElement.classList.add('text-yellow-500');
        })
        .catch(() => {
          serverStatusElement.innerHTML = '<span class="status-indicator status-error"></span> Offline';
          serverStatusElement.classList.add('text-red-500');
        });
    });
  }
});