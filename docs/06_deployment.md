# 06. Project Deployment Effort

## Use Case & Consumption
The project is deployed via a multi-tiered architecture to satisfy both the end-user (employee) and the SOC Analyst (security team).

### 1. Edge Protection (Chrome Extension)
*   A Manifest V3 compliant Google Chrome Extension serves as the first line of defense.
*   It intercepts `onBeforeRequest` web navigation events and communicates with the backend API.
*   It operates invisibly to the user until a threat is detected, at which point an interstitial warning block page is displayed.

### 2. Cloud API (Render)
*   A scalable REST API built with FastAPI/Flask.
*   Processes incoming telemetry from the Chrome Extension fleet.
*   Executes the dual-stage AI inference in real-time.

### 3. Business Intelligence Dashboard (Streamlit)
*   An interactive web dashboard for SOC analysts.
*   Used for post-incident analysis, bulk log triage, and generating C-suite reports.

## Implementation Steps
1. **Model Serialization:** Trained models (`.joblib`) were serialized and bundled into the backend infrastructure.
2. **API Containerization:** The Python backend was deployed to cloud hosting (Render), ensuring cross-origin resource sharing (CORS) was properly configured for the extension.
3. **Extension Packaging:** The `manifest.json` and background service workers were finalized, zipped, and prepared for Enterprise Group Policy deployment.
4. **Dashboard Hosting:** The Streamlit command center was launched locally (with cloud deployment capabilities) to read from the master `global_scan_history.csv`.
