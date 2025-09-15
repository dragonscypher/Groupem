// Content script to ping background and ensure MV3 service worker wakes.
try {
    chrome.runtime?.sendMessage?.({ type: 'groupem-activate' });
} catch { }
