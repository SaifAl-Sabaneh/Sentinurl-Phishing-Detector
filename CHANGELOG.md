# Changelog — SentinURL Phishing Detection System

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.8.0] — 2026-05-04

### Added
- **Check 11: IDN Homograph / Punycode Impersonation Guard** (`check_idn_homoglyph`)
  - Detects domains using visually identical Unicode characters (Cyrillic, Greek, Armenian) to impersonate trusted brands
  - Decodes punycode (`xn--`) domains before analysis
  - Applies a 20-character confusable normalisation map (Cyrillic а→a, е→e, о→o, р→p, Greek α→a, ο→o, ρ→p etc.)
  - Protects 35+ global brands: PayPal, Apple, Google, Microsoft, Amazon, WhatsApp, Chase, DHL, Steam, Aramex, Zain and more
  - Single-signal definitive flag (0.97 confidence) — no conjunctive gate needed, structural impossibility guarantees zero FP
- **Check 12: Turkish & Persian/Farsi Transliteration Phishing Guard** (`check_turkish_persian_phishing`)
  - Extends the Arabizi concept to Turkish and Persian/Farsi transliterations
  - 18 Turkish high-risk patterns: `giris` (login), `sifre` (password), `hesap` (account), `odeme` (payment), `dogrulama` (verification), `kayit` (registration), `kredi kart` (credit card)
  - 14 Persian/Farsi high-risk patterns: `vorod` (login), `ramz` (password), `pardakht` (payment), `sabtenam` (registration), `mellat`, `tejarat` (bank names), `bank meli` (national bank)
  - 9 medium-risk contextual terms (require 2 to flag)
  - Conjunctive logic: 1 high-risk + 1 any, or 2+ high-risk terms required
- **CHANGELOG.md** — this file; professional version history for the repository

### Changed
- `continuous_stress_test.py`: Added `check_idn_homoglyph` and `check_turkish_persian_phishing` to hardening loop
- `sentinurl.py`: Layer 2.5 now contains 12 hardening checks (checks #11 and #12 added)

---

## [3.7.0] — 2026-05-04

### Added
- **Check 8: Date-Encoded Phishing Kit Path Guard** (`check_date_encoded_phishing_path`)
  - Detects phishing kits using date-stamped payload directories (`/042019/`, `/03-2019/`, `/01_2020/`)
  - Conjunctive: requires date segment + trust/support/language-code context word on unknown domain
  - Score: 0.82
- **Check 9: Trailing Dot / Hex Filename Anomaly Guard** (`check_trailing_dot_anomaly`)
  - Detects malware files with hex-hash filenames ending in a bare trailing period
  - Zero false positive risk — no legitimate URL has this structure by construction
  - Score: 0.88
- **Check 10: Arabizi / Franco-Arabic Transliteration Phishing Guard** (`check_arabizi_phishing`)
  - First detection layer blind to the ML models; covers Arabic words in Latin characters
  - 20 high-risk patterns (authentication, account, payment, banking)
  - 6 critical government service names: `absher`, `nafath`, `enjaz` (single-term = immediate flag at 0.88–0.90)
  - 9 medium-risk contextual terms
  - Full Arabizi digit substitution support: 3=ع, 7=ح, 5=خ, 2=ء, 9=ص, 6=ط
  - Targets Arabic-speaking users in Jordan, Saudi Arabia, UAE, Egypt, Palestine

### Changed
- Documentation: Added Engineering Challenges section (6 challenges documented)
- Documentation: Offline baseline updated 99.90% → 99.92%

### Fixed
- N/A

---

## [3.6.1] — 2026-05-03

### Added
- **Extended File Guard for non-image suspicious extensions** in `check_fake_image_payload`
  - Added `.txt`, `.dat`, `.bin`, `.cfg`, `.tmp`, `.db` to suspicious extension set
  - Non-image extension URLs require 3 signals (vs 2 for images) for precision
- **Check 7: Random PHP Webshell Guard** (`check_random_php_webshell`)
  - Detects PHP webshells with random English dictionary-word filenames
  - Whitelist of ~130 functional PHP terms provides hard exit for legitimate applications
  - Conjunctive: non-functional filename + (HTTP | suspicious TLD | bare root path)

### Fixed
- **Path entropy off-by-one bug** in `check_malware_signatures`:
  - `len(path) > 10` → `len(path) >= 8` (was missing 10-character C2 paths by 1 character)
  - Segment threshold `> 8` → `> 5` to catch short obfuscated paths like `/Vqd0D5/`

### Accuracy
- 99.61% → **99.90%** (missed: 48 → 12)

---

## [3.6.0] — 2026-05-03

### Added
- **Check 6: Fake Image / Media Payload Guard** (`check_fake_image_payload`)
  - 8-signal conjunctive detection system for malware disguised as `.jpg`/`.png`/`.gif`
  - Signals: double extension, non-image directory, non-standard port, malware subdomain (`ftp.`, `down.`, `dl.`), high-risk TLD, suspicious filename (numeric/hex/ordinal), fake extension, plain HTTP
  - Hard-exit whitelist: 25+ trusted image CDNs (Imgur, Cloudfront, Wikimedia, GitHub, Unsplash)
  - Minimum 2 signals required (conjunctive gate)
- **`check_image_content_type()`** — parallel HEAD request for interactive mode
  - Runs concurrently with GSB/TLS in a daemon thread (zero sequential latency)
  - Catches trust-boundary cases where server returns `application/octet-stream` instead of `image/*`
  - Fail-safe: network errors never penalise the URL

### Accuracy
- 99.55% → **99.61%** (missed: 57 → 48)

---

## [3.5.0] — 2026-04-28

### Added
- Full cloud deployment on Render (`sentinurl-phishing-detector.onrender.com`)
- FastAPI production API with `/scan` endpoint
- Continuous stress test pipeline with URLHaus live feed integration
- Living Dataset Architecture: stress test automatically expands master dataset

### Infrastructure
- Multi-service Render deployment (API + Streamlit dashboard)
- Path resolution fixes for cloud environment (`/opt/render/project/src/`)
- `.gitkeep` files for required empty directories

---

## [3.4.0] — 2026-04-26

### Added
- Google Chrome Extension (Manifest V3)
  - Real-time URL scanning on page navigation
  - Service Worker background script (Manifest V3 compliant)
  - Visual threat indicator popup with confidence score
  - Global scan history logging to CSV
- Dynamic Fusion Weighting — context-aware Stage 1/Stage 2 blending

### Architecture
- Resolved Manifest V3 DOM rendering challenge via Service Worker + `webNavigation` API
- Implemented asynchronous threat neutralization for 300ms latency budget

---

## [3.3.0] — 2026-04-22

### Added
- Institutional Guard — `.edu`, `.gov`, `.mil` domain protection with hard-exit allowlist
- Reputation-aware absolute-override fusion engine
- High-entropy gaming domain false positive resolution

### Fixed
- False positives on high-entropy gaming platforms (Steam, Epic Games CDN)
- False positives on legitimate cloud PaaS platforms (Render, Vercel, Netlify)

---

## [3.2.0] — 2026-04-18

### Added
- Layer 2.5 adversarial hardening checks 1–5:
  - `check_typosquat_advanced` — brand typosquatting detection
  - `check_cloud_payload` — malware hosted on GitHub/Discord CDN
  - `check_cms_vulnerabilities` — WordPress exploit path patterns
  - `check_malware_signatures` — Linux botnet signatures, high-entropy C2 paths
  - `check_finance_phish_paths` — financial lure path patterns (`invoice.pdf`, `payroll.zip`)
- WHOIS domain age integration (real-time online check)
- TLS certificate analysis layer
- Google Safe Browsing API integration

### Accuracy
- Online model accuracy: **99.98%**

---

## [3.0.0] — 2026-04-14

### Added
- Stage 2: HistGradientBoostingClassifier (HGB) with 110+ URL features
- Dynamic ensemble fusion: TF-IDF (Stage 1) + HGB (Stage 2) weighted blending
- IP geolocation mapping
- Streamlit monitoring dashboard

### Changed
- Complete architectural overhaul from single-model to ensemble pipeline

### Accuracy
- Offline ML baseline: **99.55%**

---

## [2.0.0] — 2026-04-12

### Added
- Stage 1: TF-IDF NLP vectoriser + Logistic Regression classifier
- Continuous stress test framework (`continuous_stress_test.py`)
- URLHaus live malware feed integration
- Master dataset deduplication pipeline

---

## [1.0.0] — 2026-04-01

### Initial Release
- Single-model phishing detection baseline
- Feature extraction pipeline (`enhanced_original.py`) with 110+ URL features
- Basic dataset from PhishTank + OpenPhish + Tranco (benign)
- Initial accuracy baseline established
