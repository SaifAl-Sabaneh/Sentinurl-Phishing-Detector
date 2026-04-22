# 05. Advanced Analytics and AI Modeling

## Model Architecture
SentinURL uses a **Dual-Stage Neural Architecture** governed by a **Fusion Master Controller**.

### Stage 1: Lexical Intelligence (NLP/LogReg)
*   **Type:** Term Frequency-Inverse Document Frequency (TF-IDF) Vectorizer feeding into a Calibrated Logistic Regression model.
*   **Purpose:** Fast, edge-based parsing of the URL string. Analyzes "What the URL says."
*   **Performance:** Evaluates threats in < 4ms.

### Stage 2: Structural Fingerprinting (HGB)
*   **Type:** Histogram-based Gradient Boosting (HGB).
*   **Purpose:** Deep-dive analysis of "How the URL is built." Evaluates 110+ geometric features.
*   **Characteristics:** Selected for its native handling of missing values (imputed NaN handling) and speed over massive tabular datasets.

### The Fusion Master Controller
*   **Type:** Ensemble Logic Gate.
*   **Purpose:** Resolves disputes between Stage 1 and Stage 2 models, applying a *Structural Bias* algorithm and factoring in live Threat Intelligence telemetry (WHOIS, Domain Age).
*   **Business Logic applied:** Absolute overrides for Jordanian Trusted Domains and Global Alexa Top 100 to enforce a strict 0% false positive rate for critical business infrastructure.

## Performance Metrics
*   **Global Accuracy:** 99.55%
*   **Precision (Threat Detection):** 99.52%
*   The model prioritizes *Precision* over Recall when scanning established domains to prevent business disruption, while prioritizing *Recall* on new, low-reputation infrastructure.
