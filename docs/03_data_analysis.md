# 03. Data Description and Understanding

## Data Dictionary
The `SentinURl DataSet.csv` consists of extracted features representing the lexical and structural properties of URLs.
Key engineered fields include:
*   `url_length`: The total character count of the URL.
*   `domain_entropy`: The Shannon entropy of the domain, detecting randomized DGA (Domain Generation Algorithm) hosts.
*   `num_subdomains`: The count of subdomains. Attackers often use extensive subdomains to obfuscate the root (e.g., `login.paypal.com.secure-update.tk`).
*   `vowel_consonant_ratio`: Identifying pronounceable vs. programmatic domains.
*   `brand_spoofing_flag`: A binary indicator if a high-value brand (e.g., 'google', 'paypal') is present in the path or subdomain but not the root domain.
*   `label`: The target variable (`1` for Phishing, `0` for Safe).

## Exploratory Data Analysis (EDA)
During the initial EDA phase, several patterns were discovered:
1. **Entropy Divergence:** Phishing URLs hosted on cheap/free TLDs (.tk, .ml) exhibited significantly higher entropy than top 1000 benign domains.
2. **Path Complexity:** Phishing campaigns utilizing compromised WordPress instances had unusually deep URL paths (`/wp-content/themes/..../login.php`).
3. **Brand Keyword Abuse:** 45% of targeted phishing URLs included a top 20 brand name in the URI path.

## Primary Cleaning and Transformation
1. **Normalization:** All URLs were stripped of protocol anomalies and standardized.
2. **Feature Extraction:** The raw URL string was expanded into 110+ structural features using our `comprehensive_features.py` pipeline.
3. **Deduplication:** To prevent model bias, strict deduplication logic was applied to the master dataset, ensuring unique domain representations.
4. **Imputation:** Null values for specific geometric or WHOIS-based features were imputed with domain medians or specific flag values (`-1`).
