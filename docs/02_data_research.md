# <a id="_Toc246600772"></a><a id="_Toc1708488655"></a><a id="_Toc1914070058"></a><a id="_Toc226733465"></a>__Data Research and Acquiring Effort__

__Data Search and Selection Process__  
Building a highly accurate, robust machine learning engine required assembling a large\-scale, strictly balanced dataset that captured both historical attack behaviors and bleeding\-edge zero\-day threat patterns\. The data search process was predicted on three primary criteria:  
 __1\. Diversity of Domain Structures:__ The dataset needed to contain varied URL lexical structures across different top\-level domains \(TLDs\), including country\-code domains \(ccTLDs like \.jo\)\. This ensures that the trained Natural Language Processing Models \(TF\-IDF\) can identify character\-level entropy and anomaly patterns regardless of the hosting space\.__ \[R13\]__  
 __2\. Verified Threat Feeds:__ Raw user\-submitted lists could not be blindly trusted due to false positives\. The project required data confirmed strictly by major threat telemetry providers\.  
 __3\. Benign Sample Veracity:__ One of the hardest challenges in cybersecurity ML is acquiring reliable "safe" URLs to prevent False Positives\. We actively sought authoritative registries rather than blind website\-scraping to construct the benign portion of the dataset\.__ \[R6\]__  
__Acquisition and Sources__  
The acquisition effort blended static academic datasets with dynamically sourced intelligence feeds to train both __Stage 1 \(LogReg\)__ and __Stage 2 \(Histogram\-based Gradient Boosting\)\. \[R8\]__  
__1\. Malicious Data Acquisition \(Phishing Samples\):__  
__ __\- __PhishTank \(OpenDNS\):__ We accessed the primary PhishTank database to acquire thousands of community\-verified phishing URLs\. This data was critical for teaching the model about active credential\-harvesting schemas and structural impersonations\.__ \[R3\]__

__\- OpenPhish:__ We integrated data from OpenPhish, an independent threat intelligence provider that continuously updates zero\-day malicious feeds\. This provided insight into evolving threat structures not yet categorized by traditional blocklists\.

\- In addition to aggregating global open\-source threat intelligence, the machine learning models' training was significantly bolstered by an industry partnership with Bixah, a technology security firm\. Bixah provided specialized datasets consisting of localized, real\-world malicious URLs\. To seamlessly handle this continuous intelligence, we engineered an __Automated Dataset Enrichment Pipeline__\. This multi\-threaded Python architecture autonomously ingests Bixah's daily threat feeds, programmatically generates all 110\+ structural and heuristic features, ruthlessly deduplicates recycled domains, and appends the high\-confidence zero\-day threats directly into the Master\_SentinURL\_Dataset\.csv\.

__2\. Benign Data Acquisition \(Safe Samples\):__  
__ \- Tranco Top 1 million List:__ To train the system on legitimate traffic architecture, we utilized the Tranco List—a research\-oriented amalgamation of Alexa, Cisco Umbrella, and Majestic top websites\. This provided the ML engine with structural features of highly regulated, safe web platforms \(e\.g\., Google, Amazon, academic,\. Edu sites\)\.  
  

__\- Kaggle Domain Datasets__: We supplemented the raw arrays with structured, pre\-extracted CSV feature sets from Kaggle\. These datasets contain pre\-classified structural characteristics \(e\.g\., domain length, entropy, distinctive character counts\) to bootstrap the HistGradientBoosting model during offline training\.  
 

__3\. Live Telemetry Data \(Heuristics & Online Validation\):__  
__ __While static CSVs trained the Offline ML arrays, the system acquires real\-time data dynamically during scanning via external OSINT integration:  
 __\- Google Safe Browsing API:__ Actively cross\-references domains in real\-time as an authoritative check__ \[R19\]__\. [https://developers\.google\.com/safe\-browsing](https://developers.google.com/safe-browsing)

__\- IP\-API \(Geolocation Payload\):__ Live data pulls return latitude, longitude, and ISP origin parameters to flag unusual server mappings\. [https://ip\-api\.com/](https://ip-api.com/)

__\- WHOIS Registries:__ Acquires domain registration ages dynamically via the standard Python <a id="_Int_lQZzK5Ii"></a>whois library, feeding age parameters directly into the ultimate fusion prediction metric\.

# <a id="_Toc1161912007"></a><a id="_Toc1530182636"></a><a id="_Toc1016639301"></a><a id="_Toc226733466"></a>__Links to raw data__

1. __PhishTank \(OpenDNS\): __[https://www\.phishtank\.com/developer\_info\.php](https://www.phishtank.com/developer_info.php)
2. __OpenPhish: __[https://openphish\.com/](https://openphish.com/)
3. __Tranco Top 1 million List: __[https://tranco\-list\.eu/](https://tranco-list.eu/)
4. __Kaggle Domain Datasets__: [https://www\.kaggle\.com/datasets/shashwatwork/web\-page\-phishing\-detection\-dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
5. __Steamlit Dashboard:__ [Sentinurlgp\.streamlit\.app](https://sentinurl.streamlit.app) 
6. __GitHub Repositories__: [https://github\.com/SaifAl\-Sabaneh/Sentinurl\-Phishing\-Detector](https://github.com/SaifAl-Sabaneh/Sentinurl-Phishing-Detector)
7. __Render Dashboard \(Host\): __[https://dashboard\.render\.com/web/srv\-d799t98ule4c73ajb70g/logs?r=1h](https://dashboard.render.com/web/srv-d799t98ule4c73ajb70g/logs?r=1h)

