// contentScript.js
const EXCLUDED_PROTOCOLS = ['javascript:', 'mailto:', 'tel:', 'file:'];

/**
 * Shows a user-friendly notification overlay instead of using alert()
 * @param {string} message - The message to display
 * @param {string} type - 'error', 'warning', or 'success'
 * @param {number} duration - Time in milliseconds before auto-closing
 */
function showNotification(message, type = 'warning', duration = 5000) {
  // Remove any existing notifications
  const existingNotification = document.getElementById('security-extension-notification');
  if (existingNotification) {
    existingNotification.remove();
  }

  // Create notification container
  const notification = document.createElement('div');
  notification.id = 'security-extension-notification';
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    max-width: 400px;
    padding: 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    z-index: 2147483647;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    animation: slide-in 0.3s ease-out;
  `;

  // Style based on type
  switch (type) {
    case 'error':
      notification.style.backgroundColor = '#FEE2E2';
      notification.style.color = '#B91C1C';
      notification.style.borderLeft = '4px solid #DC2626';
      break;
    case 'success':
      notification.style.backgroundColor = '#ECFDF5';
      notification.style.color = '#065F46';
      notification.style.borderLeft = '4px solid #059669';
      break;
    default: // warning
      notification.style.backgroundColor = '#FEF3C7';
      notification.style.color = '#92400E';
      notification.style.borderLeft = '4px solid #D97706';
  }

  // Create header with icon
  const header = document.createElement('div');
  header.style.cssText = 'display: flex; align-items: center; margin-bottom: 8px; font-weight: bold;';
  
  const icon = type === 'error' ? '⚠️' : type === 'success' ? '✅' : '⚠️';
  header.textContent = `${icon} ${type.charAt(0).toUpperCase() + type.slice(1)}`;
  
  // Create close button
  const closeButton = document.createElement('div');
  closeButton.textContent = '×';
  closeButton.style.cssText = `
    position: absolute;
    top: 8px;
    right: 12px;
    font-size: 20px;
    cursor: pointer;
    color: #6B7280;
  `;
  closeButton.onclick = () => notification.remove();

  // Create message content
  const content = document.createElement('div');
  content.textContent = message;

  // Assemble notification
  notification.appendChild(closeButton);
  notification.appendChild(header);
  notification.appendChild(content);

  // Add to page
  document.body.appendChild(notification);

  // Create and inject animation styles
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slide-in {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes fade-out {
      from { opacity: 1; }
      to { opacity: 0; }
    }
  `;
  document.head.appendChild(style);

  // Auto-remove after duration
  if (duration > 0) {
    setTimeout(() => {
      notification.style.animation = 'fade-out 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, duration);
  }

  return notification;
}

// Listen for link clicks
document.addEventListener('click', (e) => {
  const link = e.target.closest('a');
  if (!link) return;

  const url = link.href;
  
  // Skip if no URL or excluded protocol
  if (!url || EXCLUDED_PROTOCOLS.some(protocol => url.startsWith(protocol))) {
    console.log('Skipping excluded URL:', url);
    return;
  }

  // Prevent navigation until we've checked the URL
  e.preventDefault();
  console.log('Link clicked:', url);

  // Check if URL is already checked and allowed
  if (link.dataset.securityChecked === 'true') {
    window.location.href = url;
    return;
  }

  // Show checking notification
  const checkingNotification = showNotification('Checking link safety...', 'warning', 0);

  // Send message to background script to check if extension is enabled
  chrome.runtime.sendMessage({ type: 'GET_ENABLED' }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Error communicating with background:', chrome.runtime.lastError);
      checkingNotification.remove();
      showNotification('Error checking extension state. Proceeding with caution.', 'error');
      window.location.href = url;
      return;
    }

    // Proceed immediately if extension is disabled
    if (response && response.enabled === false) {
      checkingNotification.remove();
      window.location.href = url;
      return;
    }

    // Check URL safety
    chrome.runtime.sendMessage({ type: 'CHECK_URL', url }, (response) => {
      checkingNotification.remove();
      
      if (chrome.runtime.lastError) {
        console.error('Error:', chrome.runtime.lastError);
        showNotification('Error checking URL. Proceed with caution.', 'error');
        return;
      }

      if (!response) {
        showNotification('No response from security check. Proceed with caution.', 'error');
        return;
      }

      if (response.isError) {
        showNotification(response.message, 'warning');
        return;
      }

      if (response.isSafe) {
        showNotification('This URL is safe.', 'success', 3000);
        
        // Mark as checked to avoid re-checking if clicked again
        link.dataset.securityChecked = 'true';
        
        // Delay navigation slightly to allow notification to be seen
        setTimeout(() => window.location.href = url, 500);
      } else {
        // Show detailed warning for unsafe URLs
        showNotification(`This URL may not be safe. ${response.message}`, 'error', 0);
      }
    });
  });
});