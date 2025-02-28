document.getElementById('toggle').addEventListener('click', () => {
  chrome.storage.local.get(['enabled'], (data) => {
    const enabled = !data.enabled;
    chrome.storage.local.set({ enabled });
    document.getElementById('status').textContent = `Extension is ${enabled ? 'active' : 'disabled'}.`;
    document.getElementById('toggle').textContent = enabled ? 'Disable' : 'Enable';
  });
});

chrome.storage.local.get(['enabled'], (data) => {
  const enabled = data.enabled !== false; // Default to true
  document.getElementById('status').textContent = `Extension is ${enabled ? 'active' : 'disabled'}.`;
  document.getElementById('toggle').textContent = enabled ? 'Disable' : 'Enable';
});