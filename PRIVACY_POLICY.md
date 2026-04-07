# Privacy Policy for SentinURL

**Effective Date:** April 2026

## 1. Introduction
SentinURL ("we," "our," or "us") is committed to protecting your privacy. This Privacy Policy explains how our Chrome Extension collects, uses, and safeguards your data. SentinURL is an academic graduation project designed to provide real-time phishing detection.

## 2. Information We Collect
To provide real-time zero-day threat detection, SentinURL requires access to certain browsing data when you use the extension:
*   **Web History (URLs):** We extract the raw URL or hostname of the websites you navigate to. 
*   **User Activity (Network Monitoring):** We monitor background web requests strictly for the purpose of intercepting connections to malicious servers before they load.

## 3. How We Use Information
The data collected is used **strictly for the single purpose** of evaluating the safety of the websites you visit:
*   The URLs you visit are transmitted securely to our external Machine Learning API.
*   Our API processes the URL structure to generate a threat probability score (Safe or Phishing).
*   The URL check is ephemeral. We do not maintain a permanent database of your browsing history.

## 4. Data Sharing and Disclosure
We respect your privacy under a zero-trust model. 
*   **We do not sell, rent, or trade your data.** 
*   **We do not use your data for advertising, creditworthiness, or lending purposes.**
*   Your data is never transferred to unauthorized third parties. 

## 5. Local Storage
We use Chrome's local storage API (`chrome.storage.local`) exclusively to cache the safety classifications of recently visited websites. This optimizes browser performance by reducing redundant API calls. This data remains on your local machine and is not synced to our servers.

## 6. Manifest V3 Compliance
SentinURL strictly adheres to Google Chrome's Manifest V3 security requirements. Our extension does not download or execute any remote code. All classification logic is securely cordoned off in our API endpoint, which only returns passive JSON data.

## 7. Contact Us
If you have any questions or concerns about this Privacy Policy or how SentinURL handles your data, please refer to our project's public repository or the contact information provided in the Chrome Web Store Developer Dashboard.
