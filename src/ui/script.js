let isScanning = false;
let globalHistory = [];

window.addEventListener('pywebviewready', function() {
    console.log("PyWebView is ready. Connected to Python backend.");
    loadHistoryFeed();
});

// ==========================================
// SETTINGS & THEME
// ==========================================
function openSettings() {
    const modal = document.getElementById('settings-modal');
    const panel = document.getElementById('settings-panel');
    modal.classList.remove('hidden');
    // slight delay for animation
    setTimeout(() => {
        modal.classList.replace('opacity-0', 'opacity-100');
        panel.classList.replace('scale-95', 'scale-100');
    }, 10);
}

function closeSettings() {
    const modal = document.getElementById('settings-modal');
    const panel = document.getElementById('settings-panel');
    modal.classList.replace('opacity-100', 'opacity-0');
    panel.classList.replace('scale-100', 'scale-95');
    setTimeout(() => modal.classList.add('hidden'), 300);
}

let isDark = true;
function toggleTheme() {
    isDark = !isDark;
    const btn = document.getElementById('theme-btn');
    if (isDark) {
        document.documentElement.classList.add('dark-theme');
        document.documentElement.classList.remove('light-theme');
        btn.innerText = "🌙 Dark";
    } else {
        document.documentElement.classList.add('light-theme');
        document.documentElement.classList.remove('dark-theme');
        btn.innerText = "☀️ Light";
    }
}

// ==========================================
// TRANSLATIONS
// ==========================================
const translations = {
    en: {
        title_scanner: "Neural Core Scanner",
        desc_scanner: "Initialize 10-layer ML fusion analysis against any global endpoint.",
        btn_demo_safe: "Demo Safe",
        btn_demo_phish: "Demo Phishing",
        btn_scan: 'SCAN <i class="fa-solid fa-bolt"></i>',
        nav_scanner: "Threat Scanner",
        nav_qr: "QR Quishing Analysis",
        nav_bulk: "Bulk Datasets",
        nav_stats: "Global Intel",
        header_recent: "Your Recent Scans",
        settings: "System Settings",
        theme: "Appearance Theme",
        theme_desc: "Toggle between Dark and Light mode",
        lang: "Language",
        lang_desc: "Select interface language",
        account: "Account Data",
        account_desc: "Manage your local scan history",
        btn_clear: "Clear History"
    },
    ar: {
        title_scanner: "الماسح الأساسي العصبي",
        desc_scanner: "بدء تحليل الاندماج متعدد الطبقات للذكاء الاصطناعي ضد أي رابط عالمي.",
        btn_demo_safe: "رابط آمن تجريبي",
        btn_demo_phish: "رابط احتيال تجريبي",
        btn_scan: 'فحص <i class="fa-solid fa-bolt"></i>',
        nav_scanner: "ماسح التهديدات",
        nav_qr: "تحليل كود QR",
        nav_bulk: "قواعد البيانات الضخمة",
        nav_stats: "المعلومات العالمية",
        header_recent: "عمليات الفحص الأخيرة",
        settings: "إعدادات النظام",
        theme: "مظهر التطبيق",
        theme_desc: "التبديل بين الوضع الداكن والفاتح",
        lang: "اللغة",
        lang_desc: "اختر لغة الواجهة",
        account: "بيانات الحساب",
        account_desc: "إدارة سجل الفحص المحلي",
        btn_clear: "مسح السجل"
    }
};

function changeLanguage() {
    const lang = document.getElementById('lang-select').value;
    const t = translations[lang];
    if (lang === 'ar') {
        document.documentElement.dir = 'rtl';
    } else {
        document.documentElement.dir = 'ltr';
    }
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if(t[key]) {
            el.innerHTML = t[key];
        }
    });
}

// ==========================================
// TABS
// ==========================================
function switchTab(tabId) {
    // Nav active state
    ['scanner', 'qr', 'bulk', 'stats'].forEach(id => {
        const btn = document.getElementById('nav-' + id);
        if (id === tabId) {
            btn.classList.add('active');
            btn.classList.remove('opacity-60', 'hover:opacity-100', 'hover:bg-black/10');
        } else {
            btn.classList.remove('active');
            btn.classList.add('opacity-60', 'hover:opacity-100', 'hover:bg-black/10');
        }
    });
    
    // View state
    ['scanner', 'qr', 'bulk', 'stats'].forEach(id => {
        const view = document.getElementById('view-' + id);
        if (id === tabId) {
            view.classList.remove('hidden');
            setTimeout(() => view.classList.replace('opacity-0', 'opacity-100'), 50);
            
            // Re-render stats if switching to stats
            if (id === 'stats') renderStatsTab();
        } else {
            view.classList.add('hidden');
            view.classList.replace('opacity-100', 'opacity-0');
        }
    });
}

function renderStatsTab() {
    const total = globalHistory.length;
    const phish = globalHistory.filter(i => i.status.includes('PHISH') || i.status.includes('HIGH')).length;
    const safe = total - phish;
    
    document.getElementById('stat-total').innerText = total;
    document.getElementById('stat-phish').innerText = phish;
    document.getElementById('stat-safe').innerText = safe;
}

// ==========================================
// SCANNER LOGIC
// ==========================================
function loadHistoryFeed() {
    if (!window.pywebview) return;
    window.pywebview.api.get_history().then(history => {
        globalHistory = history;
        const feed = document.getElementById('history-feed');
        feed.innerHTML = '';
        if (history.length === 0) {
            feed.innerHTML = '<p class="text-xs text-gray-500">No scans recorded on this account.</p>';
            return;
        }
        
        history.forEach(item => {
            const isPhish = item.status.includes('PHISH') || item.status.includes('HIGH');
            const isSusp = item.status.includes('LOW');
            const color = isPhish ? 'text-brand-phish' : isSusp ? 'text-brand-susp' : 'text-brand-safe';
            const icon = isPhish ? 'fa-shield-virus' : isSusp ? 'fa-shield-exclamation' : 'fa-shield-check';
            
            feed.innerHTML += `
                <div class="flex items-start gap-3 bg-brand-bg/50 p-3 rounded-lg border border-brand-border hover:border-brand-accent/30 transition-colors">
                    <div class="mt-0.5"><i class="fa-solid ${icon} ${color}"></i></div>
                    <div class="overflow-hidden">
                        <p class="text-xs font-bold text-[var(--color-text)] truncate w-full">${item.domain}</p>
                        <p class="text-[10px] text-gray-500 uppercase">${item.time.split(' ')[0]} • ${item.status}</p>
                    </div>
                </div>
            `;
        });
        renderStatsTab();
    });
}

function startScan() {
    if (isScanning) return;
    const url = document.getElementById('url-input').value.trim();
    if (!url) return;
    
    isScanning = true;
    
    document.getElementById('scan-btn').disabled = true;
    document.getElementById('scan-btn').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
    
    document.getElementById('blank-state').classList.add('hidden');
    document.getElementById('results-area').classList.add('hidden');
    document.getElementById('results-area').classList.remove('opacity-100', 'translate-y-0');
    
    document.getElementById('scan-overlay').classList.remove('hidden');
    document.getElementById('scan-overlay').classList.add('flex');
    
    if (window.pywebview) {
        window.pywebview.api.scan_url(url);
    }
}

window.onScanComplete = function(result) {
    isScanning = false;
    
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('scan-btn').innerHTML = 'SCAN <i class="fa-solid fa-bolt"></i>';
    
    document.getElementById('scan-overlay').classList.add('hidden');
    document.getElementById('scan-overlay').classList.remove('flex');
    
    if (result.status === 'error') {
        alert("Scan Error: " + result.message);
        return;
    }
    
    const isPhish = result.label.includes('PHISH') || result.label.includes('HIGH');
    const isSusp = result.label.includes('LOW');
    
    const vBox = document.getElementById('verdict-box');
    const vTitle = document.getElementById('verdict-title');
    const vText = document.getElementById('verdict-text');
    const vIcon = document.getElementById('verdict-icon');
    const vScore = document.getElementById('verdict-score');
    
    vBox.className = 'rounded-3xl border p-10 flex items-center justify-between shadow-2xl relative overflow-hidden group shrink-0';
    vTitle.className = 'text-6xl font-black tracking-tighter drop-shadow-lg flex items-center gap-4';
    
    if (isPhish) {
        vBox.classList.add('status-phish');
        vTitle.classList.add('text-brand-phish');
        vText.innerText = result.label;
        vIcon.className = 'fa-solid fa-shield-virus';
    } else if (isSusp) {
        vBox.classList.add('status-susp');
        vTitle.classList.add('text-brand-susp');
        vText.innerText = result.label;
        vIcon.className = 'fa-solid fa-shield-exclamation text-brand-susp';
    } else {
        vBox.classList.add('status-safe');
        vTitle.classList.add('text-brand-safe');
        vText.innerText = result.label;
        vIcon.className = 'fa-solid fa-shield-check text-brand-safe';
    }
    
    vScore.innerText = Math.round(result.score * 100);
    
    let domainStr = document.getElementById('url-input').value;
    if (!domainStr.startsWith('http')) domainStr = 'http://' + domainStr;
    const urlObj = new URL(domainStr);
    document.getElementById('m-domain').innerText = urlObj.hostname;
    
    let age = "-";
    if (result.whois && result.whois.age_days) {
        let d = result.whois.age_days;
        age = d > 365 ? `${Math.floor(d/365)}Y ${d%365}D` : `${d} Days`;
    }
    document.getElementById('m-age').innerText = age;
    document.getElementById('m-loc').innerText = (result.geo && result.geo.country) ? result.geo.country : "Unknown";
    document.getElementById('m-engine').innerText = (result.engine || "").replace(/_/g, ' ');
    
    document.getElementById('scan-time').innerHTML = `<i class="fa-solid fa-stopwatch text-brand-accent mr-1"></i> ${Math.round(result.time_ms)}ms`;
    
    const rList = document.getElementById('dd-reasons');
    rList.innerHTML = '';
    if (result.reasons && result.reasons.length > 0) {
        result.reasons.forEach(r => {
            rList.innerHTML += `<li><i class="fa-solid fa-angle-right text-brand-accent mr-2"></i>${r}</li>`;
        });
    } else {
        rList.innerHTML = '<li><i class="fa-solid fa-check text-brand-safe mr-2"></i>No malicious signatures detected.</li>';
    }
    
    const wDiv = document.getElementById('dd-whois');
    wDiv.innerHTML = '';
    if (result.whois && Object.keys(result.whois).length > 0) {
        for (const [k, v] of Object.entries(result.whois)) {
            if (v) wDiv.innerHTML += `<div><span class="text-gray-500 w-32 inline-block">${k.replace(/_/g, ' ').toUpperCase()}</span> <span class="text-[var(--color-text)]">${v}</span></div>`;
        }
    } else {
        wDiv.innerHTML = '<span class="text-gray-500">No registry data available.</span>';
    }
    
    const gDiv = document.getElementById('dd-geo');
    gDiv.innerHTML = '';
    if (result.geo && Object.keys(result.geo).length > 0) {
        for (const [k, v] of Object.entries(result.geo)) {
            if (v) gDiv.innerHTML += `<div><span class="text-gray-500 w-32 inline-block">${k.toUpperCase()}</span> <span class="text-[var(--color-text)]">${v}</span></div>`;
        }
    } else {
        gDiv.innerHTML = '<span class="text-gray-500">No telemetry data available.</span>';
    }
    
    document.getElementById('results-area').classList.remove('hidden');
    setTimeout(() => {
        document.getElementById('results-area').classList.add('opacity-100', 'translate-y-0');
        document.getElementById('results-area').classList.remove('opacity-0', 'translate-y-8');
    }, 50);
    
    loadHistoryFeed();
}
