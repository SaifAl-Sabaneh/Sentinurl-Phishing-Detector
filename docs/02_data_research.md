# 02. Data Research and Acquiring Effort

## Data Search and Justification
The project required a robust, highly diverse dataset containing both verified phishing URLs and benign, highly-trafficked domains. A static dataset would rapidly degrade in value due to the dynamic nature of phishing infrastructure. Therefore, continuous acquisition of zero-day threats was mandated.

## Acquisition Strategy
1. **Open Source Threat Intelligence (OSINT):** We integrated directly with **URLhaus**, a project by abuse.ch that tracks active malware distribution and phishing sites.
2. **Benign Data Sources:** To train the model on legitimate structure, we pulled data from Alexa Top 1 Million and established a "Jordanian Trusted Domains" list (e.g., local banks, educational institutes) to localize the model and prevent regional false positives.
3. **Automated Stress Testing:** A custom `continuous_stress_test.py` script was developed to pull 500+ fresh zero-day threats daily from URLhaus, run them through the engine, and append high-confidence failures to the training corpus.

## Data Sources
*   [URLHaus Database](https://urlhaus.abuse.ch/api/) - Active threat intelligence feed.
*   [Google Safe Browsing API](https://developers.google.com/safe-browsing) - Used for baseline verification and secondary threat intelligence.

## Description of Sources
The URLhaus feed provides the exact URL, threat tags, and timestamp of the incident. This raw feed acts as the ground truth for our active phishing samples. The benign dataset provides the necessary counter-balance to train the Machine Learning engine against false positives.
