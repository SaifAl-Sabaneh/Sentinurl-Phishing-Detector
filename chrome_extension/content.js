chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "block_page") {
        createBlockOverlay(request.riskData);
    }
});

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
        alert("This feature is disabled for your safety during the defense demo!");
    });
}
