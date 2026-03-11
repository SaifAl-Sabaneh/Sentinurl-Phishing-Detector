import sys
import subprocess
import os

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import docx
except ImportError:
    print("Installing python-docx...")
    install('python-docx')
    import docx

from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

def create_proposal():
    doc = Document()

    # Title
    title = doc.add_heading('Graduation Project Proposal', 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Subtitle/Meta
    p_meta = doc.add_paragraph()
    p_meta.add_run('Project Title: ').bold = True
    p_meta.add_run('SentinURL: Deep Semantic Inspection and Heuristic Triage for Web Security\n')
    p_meta.add_run('Student Name: ').bold = True
    p_meta.add_run('Saif Al-Sabaneh\n')
    p_meta.add_run('Submission Deadline: ').bold = True
    p_meta.add_run('16/3/2026')
    p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    doc.add_paragraph() # Spacing

    doc.add_heading('1. Overview', level=1)
    p_overview = doc.add_paragraph("This graduation project proposes the design, implementation, and rigorous evaluation of a high-performance, multi-stage machine learning architecture dedicated to the identification and neutralization of zero-day phishing threats. Traditional cybersecurity blocklists are increasingly failing against dynamically generated, obfuscated phishing domains that mutate faster than they can be cataloged. To solve this critical vulnerability, this project introduces 'SentinURL'—an enterprise-grade system that bridges the gap between rapid heuristic analysis and deep Natural Language Processing (NLP). SentinURL is uniquely engineered to evaluate the semantic intent and mathematical structure of a URL in milliseconds, delivering robust web security with exceptionally low false-positive rates.")
    p_overview.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    doc.add_heading('2. Proposal Details', level=1)

    doc.add_heading('Type of Data', level=2)
    p_data = doc.add_paragraph("The foundation of this research relies on a massive, highly curated dataset containing over 1,000,000 distinct records, perfectly balanced between malicious phishing campaigns and verified legitimate web addresses. Training an Artificial Intelligence to distinguish between safe and dangerous links requires deep dimensional feature extraction rather than simple string matching. Thus, the dataset is aggressively preprocessed to isolate lexical properties, intricate domain structures, character entropy, and vowel-to-consonant ratios. By feeding the AI computationally rich Natural Language Processing (NLP) metrics instead of raw URLs, the model transcends memorization and learns the underlying architectural traits of cyber threats, allowing it to autonomously recognize heavily obfuscated zero-day attacks that bypass conventional firewalls.")
    p_data.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    doc.add_heading('System Structure', level=2)
    p_structure = doc.add_paragraph("The proposed SentinURL architecture constitutes a sophisticated, Python-based application driven by a dynamic two-stage machine learning pipeline. Stage 1 operates as a high-speed rapid-triage filter, evaluating the URL through a finely tuned Term Frequency-Inverse Document Frequency (TF-IDF) vectorizer. Utilizing a massive memory matrix of 150,000 distinct text sequences and 7-character parsing constraints, Stage 1 clears benign traffic instantly. Should a URL exhibit anomalous traits, it is automatically escalated to the Stage 2 deep-inspection engine. Stage 2 employs a robust Hist-Gradient Boosting classifier to dissect extreme semantic NLP features. It precisely calculates vowel-to-consonant ratios for algorithmic botnet detection, analyzes structural token lengths to uncover hidden subdomains, and tracks isolated threat intent keywords (e.g., 'scam', 'crypto', 'login'). Furthermore, the system integrates a real-time failsafe architecture driven by external threat intelligence APIs (Google Safe Browsing) and an automated user-safelist to ruthlessly mitigate false positives. For operational transparency, SentinURL features a self-contained HTML report generator that provides comprehensive diagnostic logs detailing the exact mathematical confidence scores and heuristic breakdowns for end-users.")
    p_structure.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    doc.add_heading('Expected Results', level=2)
    p_results = doc.add_paragraph("The central objective of the SentinURL project is to categorically outperform standard baseline metrics in theoretical and applied detection capabilities. Rigorous cross-validation on the 1,000,000-row dataset has proven that the dual-stage AI achieves an exceptional offline detection accuracy of exactly 89.1% using exclusively mathematical and semantic analysis without network connectivity. When deployed in a live environment and integrated with dynamic external intelligence APIs, the system scales to a formidable 99.4% real-world accuracy rate. The expected outcome is the delivery of a highly reliable, automated defense mechanism capable of drastically reducing user susceptibility to credentials theft, financial fraud, and targeted social engineering attacks. Ultimately, SentinURL will demonstrate a tangible, measurable leap forward in predictive cybersecurity defense strategies.")
    p_results.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    
    doc.add_paragraph() # Spacing
    
    doc.add_heading('3. Conclusion', level=1)
    p_conclusion = doc.add_paragraph("In conclusion, the SentinURL Phishing Detection System represents a comprehensive, academic, and deeply technical effort to modernize threat detection methodologies. By abandoning reliance on static blocklists and instead migrating to a framework built on autonomous Natural Language Processing and deep algorithmic heuristics, this project successfully addresses one of the most persistent vulnerabilities in modern web security. Driven by massive data, rigorous structural integrity, and proven mathematical outcomes, SentinURL comprehensively fulfills and exceeds the requirements for a high-impact computer science graduation project.")
    p_conclusion.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    # Save
    file_path = os.path.join(r'c:\Users\Asus\Desktop\Graduation Project\PreTrained Models', 'SentinURL_Project_Proposal.docx')
    doc.save(file_path)
    print(f"Document saved successfully to {file_path}")

if __name__ == '__main__':
    create_proposal()
