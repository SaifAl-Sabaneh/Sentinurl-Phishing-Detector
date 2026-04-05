document.addEventListener('DOMContentLoaded', async () => {
    // CHANGE THIS to your deployed URL when moving to production!
    const API_URL = "http://localhost:8345/scan";

    const domainTitle = document.getElementById('domain-name');
    const badge = document.getElementById('status-badge');
    const riskCircle = document.getElementById('risk-circle');
    const scoreText = document.getElementById('risk-score');
    const reasonsList = document.getElementById('analysis-list');
    const p1Val = document.getElementById('ml1-val');
    const p2Val = document.getElementById('ml2-val');

    domainTitle.innerText = "Scanning...";

    try {
        // Get active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || !tab.url.startsWith('http')) {
            domainTitle.innerText = "Internal Browser Page";
            badge.innerText = "Ignored";
            reasonsList.innerHTML = "<li>Engine does not scan internal browser pages.</li>";
            return;
        }

        const url = new URL(tab.url);
        domainTitle.innerText = url.hostname;

        // Try getting cached result first
        chrome.storage.local.get(["status_" + tab.id], async (res) => {
            try {
                let riskData;
                
                if (res["status_" + tab.id]) {
                    riskData = res["status_" + tab.id].riskData;
                    updateUI(riskData);
                } else {
                    // If not cached, fetch it
                    domainTitle.innerText = url.hostname + "\n(Loading...)";
                    const response = await fetch(API_URL, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ url: tab.url })
                    });
                    const data = await response.json();
                    updateUI(data.data);
                }
            } catch (err) {
                console.error(err);
                domainTitle.innerText = "SentinURL API Offline";
                badge.innerText = "ERROR";
                reasonsList.innerHTML = `<li>Ensure your local API is running on localhost:8345</li>`;
            }
        });

    } catch (err) {
        console.error("Tab query failed:", err);
    }

    function updateUI(data) {
        domainTitle.innerText = new URL(data.url || document.getElementById('domain-name').innerText.replace('\n(Loading...)','')).hostname;
        
        const scorePct = Math.round(data.score * 100);
        scoreText.innerText = scorePct + "%";
        p1Val.innerText = (data.stage1_prob * 100).toFixed(1) + "%";
        p2Val.innerText = (data.stage2_prob * 100).toFixed(1) + "%";

        reasonsList.innerHTML = data.reasons.map(r => `<li>${r}</li>`).join('');

        if (data.label === "PHISHING" || data.label === "HIGH RISK") {
            badge.innerText = "🚨 Threat Detected";
            badge.className = "status-badge status-phish";
            riskCircle.className = "risk-circle phish-ring";
        } else {
            badge.innerText = "✅ Confirmed Safe";
            badge.className = "status-badge status-safe";
            riskCircle.className = "risk-circle safe-ring";
        }
    }

    // Manual Scan button
    document.getElementById('rescan-btn').addEventListener('click', () => {
        domainTitle.innerText = "Re-scanning...";
        reasonsList.innerHTML = "<li>Forcing a fresh scan...</li>";
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            try {
                const response = await fetch(API_URL, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: tabs[0].url })
                });
                const data = await response.json();
                updateUI(data.data);
            } catch(err) {
                console.error(err);
                domainTitle.innerText = "SentinURL API Offline";
                badge.innerText = "ERROR";
                reasonsList.innerHTML = `<li>Ensure your local API is running on localhost:8345</li>`;
            }
        });
    });
});
