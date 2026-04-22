# 04. Dashboard Design & Business Insights

The SentinURL Command Center is built using Streamlit, designed specifically for SOC analysts and security executives.

## Key Business Questions Answered

```
Chart 1: Security Alert Distribution (Gauge Chart)
Description: Visualizes the current distribution of analyzed URLs categorized as SAFE, SUSPICIOUS, or PHISHING.
Insight Derived: Allows the SOC manager to immediately gauge the current threat environment and the volume of incoming attacks.
```

```
Chart 2: Feature Importance / SHAP Analysis
Description: A horizontal bar chart explaining exactly which structural features of the URL triggered the ML model.
Insight Derived: Satisfies the requirement for "Explainable AI." It tells the analyst *why* the block occurred (e.g., "High Domain Entropy" or "Brand Spoofing in Path"), allowing for faster incident triage.
```

```
Chart 3: Historical Threat Timeline
Description: A time-series analysis of scans over the past 30 days.
Insight Derived: Identifies spikes in phishing campaigns targeting the organization, facilitating proactive defense adjustments.
```

```
Chart 4: Threat Intelligence Map
Description: Cross-references flagged domains with live URLHaus reporting data.
Insight Derived: Validates internal AI models against global consensus, reducing the likelihood of isolated false positives.
```
