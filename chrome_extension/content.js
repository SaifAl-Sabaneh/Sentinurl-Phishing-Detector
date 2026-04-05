chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "block_page") {
        createBlockOverlay(request.riskData);
    } else if (request.action === "show_safe") {
        showSafeToast(request.riskData);
    } else if (request.action === "show_bypassed") {
        showBypassToast(request.riskData);
    }
});

function showSafeToast(riskData) {
    if (document.getElementById("sentinurl-safe-toast")) return;

    const toast = document.createElement("div");
    toast.id = "sentinurl-safe-toast";
    
    // Smooth modern glassmorphism UI
    toast.style.cssText = `
        position: fixed; top: 20px; right: -400px; width: 320px;
        background: rgba(13, 17, 23, 0.9); backdrop-filter: blur(10px);
        border: 1px solid rgba(63, 185, 80, 0.5); border-left: 4px solid #3fb950;
        color: white; font-family: 'Segoe UI', system-ui, sans-serif;
        padding: 15px 20px; border-radius: 8px; z-index: 999999999;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        transition: right 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        display: flex; align-items: center; gap: 15px;
    `;

    toast.innerHTML = `
        <div style="font-size: 24px;">🛡️</div>
        <div>
            <div style="font-weight: bold; font-size: 14px; margin-bottom: 2px;">SentinURL Secured</div>
            <div style="font-size: 12px; color: #8b949e;">Site scanned & verified safe</div>
        </div>
    `;

    document.documentElement.appendChild(toast);

    // Slide in
    setTimeout(() => { toast.style.right = "20px"; }, 100);

    // Slide out after 3.5 seconds
    setTimeout(() => {
        toast.style.right = "-400px";
        setTimeout(() => toast.remove(), 600);
    }, 3500);
}

function showBypassToast(riskData) {
    if (document.getElementById("sentinurl-bypass-toast")) return;

    const toast = document.createElement("div");
    toast.id = "sentinurl-bypass-toast";
    
    // Smooth modern glassmorphism UI - ORANGE WARNING
    toast.style.cssText = `
        position: fixed; top: 20px; right: -400px; width: 320px;
        background: rgba(13, 17, 23, 0.9); backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 152, 0, 0.5); border-left: 4px solid #ff9800;
        color: white; font-family: 'Segoe UI', system-ui, sans-serif;
        padding: 15px 20px; border-radius: 8px; z-index: 999999999;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        transition: right 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        display: flex; align-items: center; gap: 15px;
    `;

    toast.innerHTML = `
        <div style="font-size: 24px;">⚠️</div>
        <div>
            <div style="font-weight: bold; font-size: 14px; margin-bottom: 2px; color: #ff9800;">SentinURL Bypass Active</div>
            <div style="font-size: 12px; color: #8b949e;">You are browsing a dangerous page.</div>
        </div>
    `;

    document.documentElement.appendChild(toast);

    setTimeout(() => { toast.style.right = "20px"; }, 100);

    // Bypassed tag stays on screen longer (5.5 seconds) to remind them of the risk
    setTimeout(() => {
        toast.style.right = "-400px";
        setTimeout(() => toast.remove(), 600);
    }, 5500);
}

function createBlockOverlay(riskData) {
    // If it already exists, don't create it again
    if (document.getElementById("sentinurl-block-overlay")) return;

    // Stop the actual website from showing or running
    document.body.innerHTML = '';
    document.head.innerHTML = '';
    document.documentElement.style.height = '100%';
    document.body.style.height = '100%';
    document.body.style.margin = '0';
    document.body.style.overflow = 'hidden';

    // The overlay container
    const overlay = document.createElement("div");
    overlay.id = "sentinurl-block-overlay";
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background-color: #d93025;
        color: white; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        z-index: 999999999;
    `;

    const reasonsObj = riskData.reasons.map(r => `<li>${r}</li>`).join('');

    overlay.innerHTML = `
        <div style="max-width: 800px; text-align: left; padding: 40px;">
            <h1 style="font-size: 48px; margin-bottom: 20px;">🛡️ SENTINURL BLOCKED THIS SITE</h1>
            <p style="font-size: 22px; font-weight: bold;">Dangerous website blocked by SentinURL AI Engine</p>
            <p style="font-size: 18px; line-height: 1.5;">Malicious attackers might be trying to trick you into installing software or revealing personal information (for example, passwords, phone numbers, or credit cards).</p>
            
            <div style="background: rgba(0,0,0,0.2); padding: 20px; border-radius: 8px; margin: 30px 0;">
                <h3 style="margin-top: 0;">Threat Details (Risk Score: ${Math.round(riskData.score * 100)}%)</h3>
                <ul style="font-size: 16px; margin-bottom: 0;">
                    ${reasonsObj}
                </ul>
            </div>
            
            <button id="sentinurl-back-button" style="background: white; color: #d93025; border: none; padding: 12px 24px; font-size: 16px; font-weight: bold; border-radius: 4px; cursor: pointer; margin-right: 15px;">
                Back to Safety
            </button>
            <button id="sentinurl-proceed-button" style="background: transparent; color: white; border: 1px solid white; padding: 12px 24px; font-size: 16px; font-weight: bold; border-radius: 4px; cursor: pointer;">
                I understand the risk, proceed anyway
            </button>
        </div>
    `;

    document.documentElement.appendChild(overlay);

    document.getElementById("sentinurl-back-button").addEventListener("click", () => {
        window.history.back();
    });

    document.getElementById("sentinurl-proceed-button").addEventListener("click", () => {
        // Send a message to background.js to whitelist this domain, then automatically reload
        document.getElementById("sentinurl-proceed-button").innerText = "Bypassing... Please wait.";
        chrome.runtime.sendMessage({ action: "allow_bypass", url: window.location.href });
    });
}
