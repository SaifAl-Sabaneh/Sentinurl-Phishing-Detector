// Production Deployed URL
const API_URL = "https://sentinurl-phishing-detector.onrender.com/scan";

// Keep track of scanned URLs to avoid re-scanning on every internal navigation
const scanCache = {};

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only scan main frames, not iframes
    if (details.frameId !== 0) return;

    const url = details.url;
    
    // Ignore chrome:// or internal extensions
    if (!url.startsWith('http')) return;

    // Immediately set a loading badge
    chrome.action.setBadgeText({ text: "...", tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#aaaaaa", tabId: details.tabId });

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

        // Change extension icon badge to show passive results
        if (riskData.label === "PHISHING" || riskData.label === "HIGH RISK") {
            chrome.action.setBadgeText({ text: "RISK", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#d93025", tabId: details.tabId });
            console.log("THREAT DETECTED. Blocking page...");
        } else {
            chrome.action.setBadgeText({ text: "SAFE", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#3fb950", tabId: details.tabId });
        }

        // Always inject content script to show on-page UI
        chrome.scripting.executeScript({
            target: { tabId: details.tabId },
            files: ['content.js']
        }, () => {
            setTimeout(() => {
                const actionType = (riskData.label === "PHISHING" || riskData.label === "HIGH RISK") ? "block_page" : "show_safe";
                chrome.tabs.sendMessage(details.tabId, {
                    action: actionType,
                    riskData: riskData
                }).catch(err => console.log("Message error context:", err));
            }, 100);
        });

    } catch (error) {
        console.error("SentinURL API unreachable or failed:", error);
    }
});

// Clean up storage when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.local.remove("status_" + tabId);
});
