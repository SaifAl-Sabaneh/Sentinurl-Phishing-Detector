// Production Deployed URL
const API_URL = "https://sentinurl-phishing-detector.onrender.com/scan";

// Keep track of scanned URLs to avoid re-scanning on every internal navigation
const scanCache = {};
const bypassList = new Set(); // Stores hostnames the user chose to bypass

// Listen for bypass commands from the content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "allow_bypass" && sender.tab) {
        try {
            const hostname = new URL(message.url).hostname;
            bypassList.add(hostname);
            chrome.tabs.reload(sender.tab.id); // Reload the tab immediately
        } catch(e) {}
    }
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only scan main frames, not iframes
    if (details.frameId !== 0) return;

    const url = details.url;
    
    // Ignore chrome:// or internal extensions
    if (!url.startsWith('http')) return;

    // === TOGGLE GATE: Respect user's auto-scan preference ===
    const { autoScanEnabled } = await chrome.storage.local.get(['autoScanEnabled']);
    if (autoScanEnabled === false) {
        // Clear badge so the icon looks neutral when scanning is off
        chrome.action.setBadgeText({ text: "", tabId: details.tabId });
        return;
    }

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
                body: JSON.stringify({ 
                    url: url,
                    source: "Extension-Auto"
                }),
                keepalive: true 
            });
            const data = await response.json();
            riskData = data.data;
            scanCache[url] = riskData; // Cache it
        }

        // Save current tab status for popup
        chrome.storage.local.set({ ["status_" + details.tabId]: { url, riskData } });

        const hostname = new URL(url).hostname;
        const isBypassed = bypassList.has(hostname);
        const isDangerous = riskData.label === "PHISHING" || riskData.label === "HIGH RISK";

        // Change extension icon badge to show passive results
        if (isDangerous && !isBypassed) {
            chrome.action.setBadgeText({ text: "RISK", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#d93025", tabId: details.tabId });
            console.log("THREAT DETECTED. Blocking page...");
        } else if (isDangerous && isBypassed) {
            chrome.action.setBadgeText({ text: "WARN", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#ff9800", tabId: details.tabId }); // Orange for bypassed threats
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
                let actionType = "show_safe";
                if (isDangerous && !isBypassed) actionType = "block_page";
                if (isDangerous && isBypassed) actionType = "show_bypassed";

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
