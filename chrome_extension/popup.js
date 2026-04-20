document.addEventListener('DOMContentLoaded', async () => {
    // Production Deployed URL
    const API_URL = "https://sentinurl-phishing-detector.onrender.com/scan";

    // =====================================================
    // TOGGLE: Auto-Scan ON/OFF
    // =====================================================
    const toggleEl = document.getElementById('auto-scan-toggle');
    const toggleLabel = document.getElementById('toggle-label');
    const container = document.querySelector('.container');

    // Load saved toggle state (default: ON)
    const stored = await chrome.storage.local.get(['autoScanEnabled']);
    const autoScanEnabled = stored.autoScanEnabled !== false; // default true
    toggleEl.checked = autoScanEnabled;
    updateToggleVisuals(autoScanEnabled);

    // Listen for toggle clicks
    toggleEl.addEventListener('change', async () => {
        const isOn = toggleEl.checked;
        await chrome.storage.local.set({ autoScanEnabled: isOn });
        updateToggleVisuals(isOn);
    });

    function updateToggleVisuals(isOn) {
        toggleLabel.textContent = isOn ? 'Auto' : 'Off';
        toggleLabel.classList.toggle('active', isOn);
        container.classList.toggle('extension-disabled', !isOn);

        // Show or hide the disabled notice
        const existingNotice = document.getElementById('disabled-notice');
        if (!isOn && !existingNotice) {
            const notice = document.createElement('div');
            notice.id = 'disabled-notice';
            notice.className = 'disabled-notice';
            notice.innerHTML = '⏸ Auto-scan is <strong>OFF</strong>.<br>Use <strong>Scan Current Page</strong> to manually check this site.';
            // Insert before footer
            const footer = document.querySelector('footer');
            container.insertBefore(notice, footer);
        } else if (isOn && existingNotice) {
            existingNotice.remove();
        }
    }

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
                    // No cached result — API might be cold starting on Render
                    domainTitle.innerText = url.hostname;
                    badge.innerText = "⏳ Waking up...";
                    reasonsList.innerHTML = "<li>🌐 Connecting to SentinURL Cloud API...<br><small style='color:#555'>This may take ~30s on first load</small></li>";

                    // Abort if API takes more than 25 seconds (Render cold start worst case)
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 25000);

                    try {
                        const response = await fetch(API_URL, {
                            method: "POST",
                            headers: { 
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({ 
                                url: tab.url,
                                source: "Extension-Manual"
                            }),
                            signal: controller.signal
                        });
                        clearTimeout(timeoutId);
                        const data = await response.json();
                        updateUI(data.data);
                    } catch (fetchErr) {
                        clearTimeout(timeoutId);
                        if (fetchErr.name === 'AbortError') {
                            // Cold start timeout — show helpful retry message
                            domainTitle.innerText = url.hostname;
                            badge.innerText = "⏳ Cold Start";
                            badge.className = "status-badge";
                            reasonsList.innerHTML = `
                                <li style="list-style:none; padding:0; margin:0;">
                                    <div style="text-align:center; padding: 8px 0;">
                                        <div style="font-size:22px; margin-bottom:6px;">☁️</div>
                                        <div style="color:#c9d1d9; font-weight:600; margin-bottom:4px;">API is waking up</div>
                                        <div style="color:#8b949e; font-size:12px; margin-bottom:12px;">Render free-tier servers sleep after 15min of inactivity. This takes ~30 seconds on first use.</div>
                                        <button id="retry-btn" style="width:auto; padding:8px 20px; font-size:13px; border-radius:6px;">🔄 Retry Now</button>
                                    </div>
                                </li>`;
                            document.getElementById('retry-btn')?.addEventListener('click', () => {
                                chrome.storage.local.remove("status_" + tab.id);
                                window.location.reload();
                            });
                        } else {
                            throw fetchErr;
                        }
                    }
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
        domainTitle.innerText = document.getElementById('domain-name').innerText.replace('\n(Loading...)', '');
        
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

    // Manual Input Scan button
    document.getElementById('manual-scan-btn').addEventListener('click', async () => {
        const manualInput = document.getElementById('manual-url').value.trim();
        if (!manualInput) return;
        
        let targetUrl = manualInput;
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
            targetUrl = 'http://' + targetUrl;
        }

        try {
            const parsedUrl = new URL(targetUrl);
            domainTitle.innerText = parsedUrl.hostname + "\n(Loading...)";
            reasonsList.innerHTML = "<li>Scanning custom URL via Engine...</li>";
            
            const response = await fetch(API_URL, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ 
                    url: targetUrl,
                    source: "Extension-Manual"
                })
            });
            const data = await response.json();
            updateUI(data.data);
        } catch(err) {
            console.error(err);
            domainTitle.innerText = "Scan Failed";
            badge.innerText = "ERROR";
            reasonsList.innerHTML = `<li>Invalid URL or API Offline.</li>`;
        }
    });

    // Manual Scan button
    document.getElementById('rescan-btn').addEventListener('click', () => {
        domainTitle.innerText = "Re-scanning...";
        reasonsList.innerHTML = "<li>Forcing a fresh scan...</li>";
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            try {
                const response = await fetch(API_URL, {
                    method: "POST",
                    headers: { 
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ 
                        url: tabs[0].url,
                        source: "Extension-Manual"
                    })
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
