// CHANGE THIS to your deployed URL when moving to production!
const API_URL = "http://localhost:8345/scan";

// Keep track of scanned URLs to avoid re-scanning on every internal navigation
const scanCache = {};

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only scan main frames, not iframes
    if (details.frameId !== 0) return;

    const url = details.url;
    
    // Ignore chrome:// or internal extensions
    if (!url.startsWith('http')) return;

    try {
        console.log(`SentinURL intercepted: ${url}`);
        
        let riskData;
        if (scanCache[url]) {
            riskData = scanCache[url];
        } else {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: url })
            });
            const data = await response.json();
            riskData = data.data;
            scanCache[url] = riskData; // Cache it
        }

        // Save current tab status for popup
        chrome.storage.local.set({ ["status_" + details.tabId]: { url, riskData } });

        // If high risk or phishing, inject our content script to overlay the red screen
        if (riskData.label === "PHISHING" || riskData.label === "HIGH RISK") {
            console.log("THREAT DETECTED. Blocking page...");
            chrome.scripting.executeScript({
                target: { tabId: details.tabId },
                files: ['content.js']
            }, () => {
                // After executing the script, send a message to trigger the block
                setTimeout(() => {
                    chrome.tabs.sendMessage(details.tabId, {
                        action: "block_page",
                        riskData: riskData
                    }).catch(err => console.log("Message error (normal on fast redirects):", err));
                }, 100);
            });
        }
    } catch (error) {
        console.error("SentinURL API unreachable or failed:", error);
    }
});

// Clean up storage when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.local.remove("status_" + tabId);
});
