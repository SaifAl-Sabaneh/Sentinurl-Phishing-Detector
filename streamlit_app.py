import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from urllib.parse import urlparse
import time
import os
import sys
import json
import random
from datetime import datetime

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from sentinurl import predict_ultimate
from enhanced_original import url_features

# --- Constants & State ---
HISTORY_FILE = "scan_history.csv"

# --- Page Configuration ---
st.set_page_config(
    page_title="SentinURL | Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Helper Functions ---
def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            return pd.read_csv(HISTORY_FILE)
        except:
            pass
    return pd.DataFrame(columns=["timestamp", "domain", "url", "status", "risk_score_percent", "decision_by"])

def save_history(record_dict):
    df = load_history()
    new_row = pd.DataFrame([record_dict])
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(HISTORY_FILE, index=False)

def format_engine_name(engine_id):
    engine_id = str(engine_id)
    mapping = {
        "allowlist_reg_domain": "Trusted Allowlist (Registered Domain)",
        "allowlist_jordanian_official": "Trusted Allowlist (Government)",
        "demo_phishing_rule": "Live Presenter Match (Demo Override)",
        "threat_intelligence_match": "Threat Intelligence Database",
        "advanced_brand_impersonation": "Brand Impersonation Guard",
        "fusion_offline_online": "ML Fusion Network (Offline + Online)",
        "rule_ip_host": "Heuristics Rule (IP Target Base)"
    }
    return mapping.get(engine_id, engine_id.replace("_", " ").title())

def create_gauge_chart(score):
    color = "green"
    if score > 70:
        color = "red"
    elif score > 40:
        color = "orange"
        
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Phishing Probability", 'font': {'size': 20}},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1},
            'bar': {'color': color},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 2,
            'steps': [
                {'range': [0, 40], 'color': 'rgba(46, 204, 113, 0.3)'},
                {'range': [40, 70], 'color': 'rgba(243, 156, 18, 0.3)'},
                {'range': [70, 100], 'color': 'rgba(231, 76, 60, 0.3)'}],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 75}
        }
    ))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={'family': "Arial"},
        height=300,
        margin=dict(l=20, r=20, t=50, b=20)
    )
    return fig

# --- Sidebar UI ---
with st.sidebar:
    st.image("https://img.icons8.com/nolan/256/shield.png", width=100)
    st.title("SentinURL")
    st.caption("Advanced Phishing Detection Engine")
    
    st.markdown("---")
    
    st.subheader("⏱️ Recent Scans")
    hist_df = load_history()
    if hist_df.empty:
        st.info("No URLs scanned yet.")
    else:
        # Show last 5
        recent_hist = hist_df.tail(5).iloc[::-1]
        for _, row in recent_hist.iterrows():
            is_phish = row['status'].lower() == 'phishing'
            card_class = "history-card-phish" if is_phish else "history-card-safe"
            icon = "🚨" if is_phish else "✅"
            
            st.markdown(f'''
            <div style="border-left: 4px solid {'#e74c3c' if is_phish else '#2ecc71'}; padding-left: 10px; margin-bottom: 10px; color: var(--text-color);">
                <b>{icon} {row["domain"]}</b><br>
                <small>{row["timestamp"]}</small>
            </div>
            ''', unsafe_allow_html=True)
            
        if st.button("Clear History"):
            if os.path.exists(HISTORY_FILE):
                os.remove(HISTORY_FILE)
            st.rerun()

    st.markdown("---")
    st.subheader("About the System")
    st.info("""
    This graduation project utilizes a hybrid machine learning approach to detect malicious URLs.
    
    **Core Engines:**
    - 🌳 **Random Forest:** Handles text and lexical features.
    - 🚀 **CatBoost:** Processes categorical and complex behavioral data.
    """)
    st.caption("Developed for Final Year Project - 2026")

# --- Custom CSS for Styling ---
st.markdown("""
<style>
    .main .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
    .summary-header { font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem; color: var(--text-color); }
    
    .result-box-safe {
        padding: 20px; border-radius: 10px; text-align: center; margin-bottom: 20px;
        background-color: rgba(40, 167, 69, 0.1); border: 2px solid #28a745;
        animation: fadeIn 0.5s ease-in;
    }
    .result-box-phishing {
        padding: 20px; border-radius: 10px; text-align: center; margin-bottom: 20px;
        background-color: rgba(220, 53, 69, 0.1); border: 2px solid #dc3545;
        animation: pulseBorder 1.5s infinite;
    }
    
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulseBorder { 0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7); } 70% { box-shadow: 0 0 0 15px rgba(220, 53, 69, 0); } 100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); } }
    
    .result-title { font-size: 2.5rem; font-weight: bold; margin-bottom: 10px; }
    .safe-text { color: #2ecc71; }
    .phishing-text { color: #e74c3c; }
</style>
""", unsafe_allow_html=True)


# --- Top Level Tabs ---
tab_scan, tab_batch, tab_stats = st.tabs(["🔍 Single URL Scan", "📁 Batch CSV Scanner", "📈 Global Statistics"])

# --- Data Loading for Generator ---
@st.cache_data
def load_url_dataset():
    # current_dir is defined at the top of the file
    parent_dir = os.path.dirname(current_dir)
    dataset_path = os.path.join(parent_dir, "Phishing Dataset.csv")
    try:
        if os.path.exists(dataset_path):
            df = pd.read_csv(dataset_path)
            if 'URL' in df.columns and 'Type' in df.columns:
                return df
    except Exception as e:
        pass # Silently fail into fallback
    return pd.DataFrame()

def get_random_url_hybrid(url_type="Safe"):
    # 1. Initialize session state for tracking used URLs
    if "used_urls" not in st.session_state:
        st.session_state.used_urls = set()
        
    df = load_url_dataset()
    
    # Fallback hardcoded lists if dataset fails
    fallbacks = {
        "Safe": [
            "https://github.com", "https://stackoverflow.com", "https://wikipedia.org", "https://microsoft.com",
            "https://www.apple.com", "https://www.python.org", "https://www.netflix.com", "https://aws.amazon.com",
            "https://openai.com", "https://www.spotify.com", "https://news.ycombinator.com", "https://reddit.com"
        ],
        "Phishing": [
            "http://1.1.1.1", "http://login-update-security-alert.xyz", "http://free-netflix-subscription.top", 
            "http://verify-bank-account-now.com", "http://paypal-security-auth-check.net", "http://secure-login-amazon-update.org",
            "http://apple-id-verification-suspended.com", "http://win-free-iphone-15-now.store", "http://admin-panel-login-portal.site",
            "http://customer-support-refund-desk.info"
        ]
    }
    
    # 2. Try to get from dataset first
    if not df.empty:
        # Filter by type
        type_df = df[df['Type'].str.lower() == url_type.lower()]
        if not type_df.empty:
            # Filter out already used URLs
            available_urls = type_df[~type_df['URL'].isin(st.session_state.used_urls)]
            
            if not available_urls.empty:
                # Pick a random one
                chosen_url = available_urls.sample(n=1)['URL'].iloc[0]
                st.session_state.used_urls.add(chosen_url)
                return chosen_url
            else:
                st.toast(f"ℹ️ All {url_type} URLs from dataset have been shown. Resetting or using fallback.")
                # We could reset the used list here, but let's fall through to fallbacks
                
    # 3. Fallback to hardcoded (also track these)
    available_fallbacks = [u for u in fallbacks[url_type] if u not in st.session_state.used_urls]
    if available_fallbacks:
        chosen_url = random.choice(available_fallbacks)
        st.session_state.used_urls.add(chosen_url)
        return chosen_url
    else:
        # Total exhaustion of dataset and fallbacks: Reset the tracker
        st.session_state.used_urls.clear()
        chosen_url = random.choice(fallbacks[url_type])
        st.session_state.used_urls.add(chosen_url)
        return chosen_url

# ==========================================
# TAB 1: SINGLE URL SCAN
# ==========================================
with tab_scan:
    st.title("URL Threat Scanner")
    st.markdown("Enter a website URL below to analyze it for phishing indicators.")
    
    if "demo_url" not in st.session_state:
        st.session_state.demo_url = ""

    col_btn1, col_btn2 = st.columns([1, 1])
    with col_btn1:
        if st.button("✅ Load Random Safe URL", use_container_width=True):
            st.session_state.demo_url = get_random_url_hybrid("Safe")
            st.rerun() # Force UI update immediately so the input box shows the new URL
    with col_btn2:
        if st.button("🚨 Load Random Phishing URL", use_container_width=True):
            st.session_state.demo_url = get_random_url_hybrid("Phishing")
            st.rerun() # Force UI update immediately

    with st.form(key='scan_form'):
        col1, col2 = st.columns([4, 1])
        with col1:
            url_input = st.text_input("Website URL", value=st.session_state.demo_url, placeholder="e.g., https://www.secure-login-example.com", label_visibility="collapsed")
        with col2:
            submit_button = st.form_submit_button(label='Scan URL', use_container_width=True, type="primary")

    if submit_button:
        if not url_input:
            st.warning("⚠️ Please enter a URL to scan.")
        else:
            if not url_input.startswith("http"):
                 url_input = "http://" + url_input

            parsed_url = urlparse(url_input)
            domain = parsed_url.netloc or url_input
            
            with st.spinner(f"Analyzing {domain}... Engine running."):
                time.sleep(0.5) 
                
                try:
                    # ML Engine Calls
                    label, score_prob, decision_by, reasons, p1, p2, whois_data, geo_info = predict_ultimate(url_input)
                    extracted_feats = url_features(url_input)  # New Feature 3 logic
                    
                    # Process Results
                    safe_score = score_prob if score_prob is not None else 0.0
                    risk_score_percent = int(safe_score * 100)
                    
                    safe_label = str(label).lower() if label is not None else "unknown"
                    is_phishing = safe_label == "phishing" or safe_label == "bad"
                    status_str = "Phishing" if is_phishing else "Safe"
                    
                    # Persist to disk (Feature 2 logic)
                    save_history({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "domain": domain,
                        "url": url_input,
                        "status": status_str,
                        "risk_score_percent": risk_score_percent,
                        "decision_by": decision_by
                    })

                    # Animations (Feature 5: Balloons completely removed)
                    if is_phishing:
                        st.toast('🚨 Warning! High Threat Level Detected', icon='🚨')

                    # Result Display
                    st.markdown("---")
                    
                    if is_phishing:
                        st.markdown(f"""
                        <div class="result-box-phishing">
                            <div class="result-title phishing-text">🚨 PHISHING DETECTED</div>
                            <div>This website exhibits strong indicators of being a malicious or deceptive site.</div>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="result-box-safe">
                            <div class="result-title safe-text">✅ SAFE WEBSITE</div>
                            <div>This website appears to be legitimate and safe to visit.</div>
                        </div>
                        """, unsafe_allow_html=True)

                    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
                    
                    age_display = "Unknown"
                    age_days_val = None
                    if whois_data and whois_data.get('age_days') is not None:
                        age_days_val = whois_data.get('age_days')
                        if age_days_val > 365:
                            age_display = f"{age_days_val//365} Years"
                        else:
                            age_display = f"{age_days_val} Days"
                            
                    country_display = "Unknown"
                    if geo_info and geo_info.get("country"):
                        country_display = geo_info.get("country")
                        
                    clean_decision_by = format_engine_name(decision_by)

                    with mcol1:
                        st.metric("Target Domain", domain, help="The primary network location being analyzed.")
                    with mcol2:
                        is_new_domain = age_days_val is not None and age_days_val < 180
                        st.metric("Domain Age", age_display, delta="Warning" if is_new_domain else "Established", delta_color="inverse", help="Phishing endpoints are usually less than 6 months old. Legitimate sites are typically older.")
                    with mcol3:
                        st.metric("Server Location", country_display, help="The geographic location where this website is physically hosted based on its IP address.")
                    with mcol4:
                        st.metric("Decision Engine", clean_decision_by, help="Which specific layer of the ML pipeline (Random Forest, CatBoost, Threat Intel, etc.) made the final judgment.")

                    st.markdown(" ") 
                    res_col1, res_col2 = st.columns([1, 1.5])
                    
                    with res_col1:
                        st.markdown('<div class="summary-header">Threat Analysis</div>', unsafe_allow_html=True)
                        fig = create_gauge_chart(risk_score_percent)
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with res_col2:
                        st.markdown('<div class="summary-header">Detection Reasons</div>', unsafe_allow_html=True)
                        if not reasons:
                             st.success("No suspicious indicators found.")
                        else:
                            for reason in reasons:
                                if "Low" in reason or "Safe" in reason or "clean" in reason.lower() or "prevent" in reason.lower():
                                    st.info(f"ℹ️ {reason}")
                                else:
                                    st.error(f"⚠️ {reason}")
                                    
                    st.markdown("---")
                    st.subheader("Deep Dive Analysis")
                    
                    # Added Feature 3: Extracted Features tab!
                    d_tab1, d_tab2, d_tab3, d_tab4, d_tab5, d_tab6 = st.tabs([
                        "🌐 Domain Identity", "🌍 Network & Geo", "🤖 Engine Breakdown", 
                        "📍 Server Map", "🔬 Extracted Features", "💻 Raw JSON"
                    ])
                    
                    with d_tab1:
                        if whois_data:
                            clean_whois = {k: str(v) for k, v in whois_data.items() if v}
                            wcol1, wcol2 = st.columns(2)
                            with wcol1:
                                 st.write("**Registrar:**", clean_whois.get("registrar", "Hidden/Unknown"))
                                 st.write("**Creation Date:**", clean_whois.get("creation_date", "Unknown"))
                                 st.write("**Expiration Date:**", clean_whois.get("expiration_date", "Unknown"))
                            with wcol2:
                                 st.write("**Updated Date:**", clean_whois.get("updated_date", "Unknown"))
                                 st.write("**Name Servers:**", clean_whois.get("nameservers", "Unknown"))
                        else:
                            st.info("WHOIS data could not be retrieved or is protected.")
                            
                    with d_tab2:
                        if geo_info:
                            gcol1, gcol2 = st.columns(2)
                            with gcol1:
                                st.write("**IP Address:**", geo_info.get("query", geo_info.get("ip", "Unknown")))
                                st.write("**ISP:**", geo_info.get("isp", "Unknown"))
                                st.write("**Organization:**", geo_info.get("org", "Unknown"))
                            with gcol2:
                                st.write("**City:**", geo_info.get("city", "Unknown"))
                                st.write("**Region:**", geo_info.get("regionName", "Unknown"))
                                st.write("**Country:**", geo_info.get("country", "Unknown"))
                                st.write("**AS Number:**", geo_info.get("as", "Unknown"))
                        else:
                            st.info("Geographic network data could not be retrieved.")
                            
                    with d_tab3:
                        p1_val = (p1 * 100) if p1 is not None else 0.0
                        p2_val = (p2 * 100) if p2 is not None else 0.0
                        prob_data = pd.DataFrame({
                            "Engine": ["Random Forest (Stage 1)", "CatBoost (Stage 2)"],
                            "Phishing Probability (%)": [p1_val, p2_val]
                        })
                        
                        fig_bar = px.bar(prob_data, x="Engine", y="Phishing Probability (%)", text="Phishing Probability (%)", color="Engine", color_discrete_sequence=['#3498db', '#9b59b6'])
                        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", showlegend=False)
                        st.plotly_chart(fig_bar, use_container_width=True)
                        st.caption("Note: The final 'Decision Engine' dictates which model's probability was chosen.")

                    with d_tab4:
                        if geo_info and geo_info.get("lat") and geo_info.get("lon"):
                            try:
                                lat = float(geo_info.get("lat"))
                                lon = float(geo_info.get("lon"))
                                df_map = pd.DataFrame({'lat': [lat], 'lon': [lon]})
                                st.map(df_map, zoom=4, color="#e74c3c", size=500)
                            except ValueError:
                                st.warning("Could not parse coordinates for mapping.")
                        else:
                            st.info("No GPS coordinates found for this server IP.")

                    # Feature 3: Extracted features
                    with d_tab5:
                        st.write("These are the raw lexical and structural features extracted from the URL and fed into the AI Model.")
                        feats_df = pd.DataFrame(list(extracted_feats.items()), columns=["Feature Name", "Value"])
                        st.dataframe(feats_df, use_container_width=True)

                    with d_tab6:
                        raw_data = {
                            "url": url_input, "final_verdict": status_str,
                            "risk_computed": score_prob, "reasons": reasons,
                            "whois": whois_data, "geo": geo_info
                        }
                        st.json(raw_data)

                    # Export Report
                    st.markdown("---")
                    with st.columns([1, 4])[0]:
                        st.download_button(
                            label="📄 Download Analysis Report",
                            data=f"Verdict: {status_str}\nRisk: {risk_score_percent}%\nURL: {url_input}\nReasons:\n" + "\n".join(reasons),
                            file_name=f"report_{domain}.txt",
                            mime="text/plain",
                            type="primary"
                        )

                except Exception as e:
                    import traceback
                    st.error("An error occurred during scanning.")
                    with st.expander("Show Details"):
                         st.code(traceback.format_exc())


# ==========================================
# TAB 2: BATCH CSV SCANNER
# ==========================================
with tab_batch:
    st.title("📁 Bulk Threat Scanner")
    st.write("Upload a CSV file containing a list of URLs to scan multiple domains simultaneously. Your CSV MUST contain a column named `url` or `URL`.")
    
    uploaded_file = st.file_uploader("Upload CSV File", type="csv")
    if uploaded_file is not None:
        try:
            # Try robust reading for different encodings
            try:
                df_upload = pd.read_csv(uploaded_file, encoding='utf-8')
            except UnicodeDecodeError:
                try:
                    uploaded_file.seek(0)
                    df_upload = pd.read_csv(uploaded_file, encoding='ISO-8859-1')
                except UnicodeDecodeError:
                    uploaded_file.seek(0)
                    df_upload = pd.read_csv(uploaded_file, encoding='utf-8', encoding_errors='ignore')
            
            # Find the URL column
            url_col = None
            for col in df_upload.columns:
                if col.lower().strip() == 'url':
                    url_col = col
                    break
            
            if url_col is None:
                st.error("Error: The uploaded CSV does not contain a column named 'url'. Please rename your column and try again.")
            else:
                st.success(f"Successfully loaded {len(df_upload)} URLs.")
                
                if st.button("🚀 Start Bulk Scan", type="primary"):
                    progress_text = st.empty()
                    progress_bar = st.progress(0)
                    
                    # Create placeholder for Live View
                    st.markdown("### 🔴 Live View (Latest 15 Scans)")
                    live_table_placeholder = st.empty()
                    
                    results_list = []
                    live_scans = [] # Tracks the rolling window
                    
                    for i, row in df_upload.iterrows():
                        target_url = str(row[url_col])
                        progress_text.text(f"Scanning ({i+1}/{len(df_upload)}): {target_url}")
                        
                        target_url_fmt = target_url if target_url.startswith("http") else "http://" + target_url
                        
                        try:
                            lbl, score_prob, decision_by, _, _, _, _, _ = predict_ultimate(target_url_fmt)
                            
                            safe_score = score_prob if score_prob is not None else 0.0
                            is_phishing = str(lbl).lower() in ["phishing", "bad", "high risk", "suspicious"]
                            
                            clean_decision_by = format_engine_name(decision_by)
                            
                            scan_result = {
                                "URL": target_url,
                                "Status": "Phishing" if is_phishing else "Safe",
                                "Risk Score (%)": int(safe_score * 100),
                                "Engine": clean_decision_by
                            }
                            
                            results_list.append(scan_result)
                            
                            # Keep only top 15 for live view so it stays fast
                            live_scans.insert(0, scan_result)
                            if len(live_scans) > 15:
                                live_scans.pop()
                                
                            # Update UI Live
                            live_table_placeholder.dataframe(pd.DataFrame(live_scans), use_container_width=True)
                            
                            # Persist bulk scan items to history too!
                            save_history({
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "domain": urlparse(target_url_fmt).netloc,
                                "url": target_url_fmt,
                                "status": scan_result["Status"],
                                "risk_score_percent": scan_result["Risk Score (%)"],
                                "decision_by": clean_decision_by
                            })
                            
                        except Exception as e:
                            error_res = {
                                "URL": target_url,
                                "Status": "Error",
                                "Risk Score (%)": 0,
                                "Engine": str(e)
                            }
                            results_list.append(error_res)
                            
                            live_scans.insert(0, error_res)
                            if len(live_scans) > 15:
                                live_scans.pop()
                            live_table_placeholder.dataframe(pd.DataFrame(live_scans), use_container_width=True)
                            
                        progress_bar.progress((i + 1) / len(df_upload))
                        
                    progress_text.text("Scan Complete!")
                    
                    res_df = pd.DataFrame(results_list)
                    st.write("### 🏁 Final Bulk Scan Results")
                    
                    # Compute statistics
                    total_scanned = len(res_df)
                    total_phishing = len(res_df[res_df["Status"] == "Phishing"])
                    total_safe = len(res_df[res_df["Status"] == "Safe"])
                    total_errors = len(res_df[res_df["Status"] == "Error"])
                    
                    # Display metrics dashboard
                    st.markdown("#### 📊 Bulk Scan Analytics")
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Total URLs Scanned", total_scanned)
                    m2.metric("Phishing Detected", total_phishing)
                    m3.metric("Safe URLs", total_safe)
                    m4.metric("Scan Errors", total_errors)
                    
                    st.markdown("---")
                    
                    st.dataframe(res_df, use_container_width=True)
                    
                    csv_export = res_df.to_csv(index=False).encode('utf-8')
                    st.download_button("⬇️ Download Full Results as CSV", data=csv_export, file_name="bulk_scan_results.csv", mime="text/csv")
                    
        except Exception as e:
            st.error(f"Error reading CSV: {e}")

# ==========================================
# TAB 3: GLOBAL STATISTICS
# ==========================================
with tab_stats:
    st.title("📈 Global Statistics & Trends")
    st.write("Historical data from all local scans across sessions.")
    
    hist_stats = load_history()
    
    if hist_stats.empty:
        st.info("No scan history found. Start scanning URLs to build statistics.")
    else:
        stcol1, stcol2, stcol3 = st.columns(3)
        
        total_scans = len(hist_stats)
        phishing_hits = len(hist_stats[hist_stats['status'] == 'Phishing'])
        safe_hits = total_scans - phishing_hits
        
        stcol1.metric("Total Scans Performed", total_scans)
        stcol2.metric("Phishing Submissions", phishing_hits)
        stcol3.metric("Safe Submissions", safe_hits)
        
        c1, c2 = st.columns(2)
        
        with c1:
            st.markdown("### Safe vs Phishing Breakdown")
            # Donut chart
            labels = ['Phishing', 'Safe']
            values = [phishing_hits, safe_hits]
            colors = ['#EF553B', '#00CC96']
            
            fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.5)])
            fig.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                              marker=dict(colors=colors, line=dict(color='#000000', width=2)))
            
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
            
        with c2:
            st.markdown("### Top Detection Engines")
            engine_counts = hist_stats['decision_by'].value_counts().reset_index()
            engine_counts.columns = ['Engine', 'Count']
            
            fig2 = px.bar(engine_counts, x='Engine', y='Count', text='Count',
              color='Count', color_continuous_scale=px.colors.sequential.Agsunset)
            
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig2, use_container_width=True)
            
        st.write("### Raw History Log")
        st.dataframe(hist_stats, use_container_width=True)
