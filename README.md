# 🛡️ SentinURL: AI-Driven Phishing Detection & Risk Intelligence

![Version](https://img.shields.io/badge/Version-3.6.0-blue)
![Accuracy](https://img.shields.io/badge/Accuracy-99.55%25-green)
![License](https://img.shields.io/badge/License-Creative_Commons-orange)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)

**SentinURL** is an enterprise-grade threat intelligence engine that leverages a multi-stage Machine Learning architecture to neutralize zero-day phishing and malware campaigns in real-time. Designed at the intersection of **Cybersecurity** and **Business Intelligence**, it transforms raw URL telemetry into actionable defensive insights.

---

## 🚀 Performance & Intelligence
*   **Verified Global Accuracy:** **99.55%** (validated against 12,000+ live URLHaus zero-day threats).
*   **Ultra-Low Latency:** < 4ms evaluation time via a optimized Stage 1 NLP engine.
*   **Edge Protection:** Real-time interception via a **Google Chrome Extension (MV3)**.
*   **Quishing Defense:** Integrated QR-code decoding and scanning pipeline.
*   **Fail-Safe Engine:** Reputation-aware absolute overrides to ensure 0% business friction for established domains.

---

## 🧠 Dual-Stage Neural Architecture
SentinURL utilizes a modular ensemble approach to capture threats that traditional "black-box" models miss.

### **1. Stage 1: Lexical Intelligence (NLP/LogReg)**
Analyzes "What the URL says." Utilizing **TF-IDF N-Grams** and Calibrated Logistic Regression, this layer identifies deceptive language patterns and social engineering keywords at millisecond speeds.

### **2. Stage 2: Structural Fingerprinting (HGB)**
Analyzes "How the URL is built." It evaluates 110+ structural features, including **Shannon Entropy**, subdomain depth, and character distribution using a **Histogram-based Gradient Boosting** model.

### **3. The Fusion Master Controller**
The "Supreme Court" of the system. It synthesizes outputs from both ML stages and live telemetry feeds (GSB, WHOIS, TLS) using a **Structural Bias** logic to resolve conflicts with high precision.

---

## 📊 Business Intelligence Dashboard
The system includes a professional **Streamlit Command Center** designed for SOC (Security Operations Center) analysts:
*   **Investigative Triage:** Bulk-process URL logs to identify campaign trends.
*   **Explanable AI (XAI):** Visual breakdown of the mathematical reasons behind every block.
*   **Live Threat Intel:** Integration with Global Threat Feeds (URLHaus).
*   **Executive Reporting:** One-click PDF generation for C-suite risk assessment.

---

## 🛠️ Deployment & Orchestration
*   **Cloud API (Render):** Scalable REST API backend for multi-client protection.
*   **Chrome Extension:** Manifest V3 compliant real-time edge protection.
*   **Continuous Stress Test:** Automated daily health-monitoring and dataset refinement.

---

## 📥 Getting Started
```bash
# Install dependencies
pip install -r requirements.txt

# Launch the BI Dashboard
streamlit run streamlit_app.py
```

---

## 🎓 Ownership & Academic Context
Developed as a **Business Intelligence & Data Analytics Graduation Project** by **Saif Al-Sabaneh** (2025/2026). SentinURL represents a case study in applying predictive analytics to mitigate high-stakes corporate financial risk.

---
*Securing the digital frontier, one URL at a time.*
