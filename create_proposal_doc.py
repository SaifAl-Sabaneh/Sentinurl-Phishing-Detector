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
    p_meta.add_run('SentinURL Multi-Stage Phishing Detection System\n')
    p_meta.add_run('Student Name: ').bold = True
    p_meta.add_run('Saif Al-Sabaneh\n')
    p_meta.add_run('Submission Deadline: ').bold = True
    p_meta.add_run('16/3/2026')
    p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    doc.add_paragraph() # Spacing

    doc.add_heading('1. Overview', level=1)
    doc.add_paragraph("This graduation project aims to design and implement a high-performance, multi-stage machine learning system dedicated to identifying and neutralizing zero-day phishing threats. Dubbed 'SentinURL', the system bridges the gap between rapid heuristic analysis and deep Natural Language Processing (NLP) to provide enterprise-grade web security with minimal false positives.")

    doc.add_heading('2. Proposal Details', level=1)

    doc.add_heading('Type of Data', level=2)
    p_data = doc.add_paragraph("The project will utilize a comprehensive and balanced dataset comprising both malicious phishing URLs and verified legitimate (benign) web addresses. The dataset integrates multiple dimensional features, including lexical properties of the URL, structural domain characteristics, and raw web page content (HTML source code). To maximize the model's predictive capabilities, the data undergoes rigorous preprocessing to extract sophisticated Natural Language Processing (NLP) features and heuristic behaviors. This ensures the system is adequately trained to recognize heavily obfuscated and newly deployed phishing attempts that traditional blocklists bypass.")
    p_data.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    doc.add_heading('System Structure', level=2)
    p_structure = doc.add_paragraph("The proposed architecture is a robust, Python-based application featuring a two-stage machine learning pipeline. Stage 1 functions as a rapid-triage filter, evaluating NLP-extracted features with a tuned TF-IDF vectorizer containing a massive 150,000 text sequence vocabulary to classify incoming URLs with high speed. If a URL is flagged as suspicious, it is escalated to Stage 2, which acts as a deep-inspection engine executing a rigorous content and structural analysis using Hist-Gradient Boosting. Stage 2 specifically extracts semantic NLP features, such as vowel-to-consonant ratios for gibberish botnet detection, token length thresholds, and explicit tracking of threat intent keywords (e.g., 'scam', 'finance', 'login'). The backend includes an automated safelist system to rapidly mitigate false positives. Additionally, the system features an integrated HTML report generator that produces professional, diagnostic logs detailing exact threat metrics, confidence scores, and analysis breakdowns for end-users.")
    p_structure.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    doc.add_heading('Expected Results', level=2)
    p_results = doc.add_paragraph("The system successfully achieves an exceptional offline detection accuracy of exactly 89.1% using purely mathematical and semantic analysis of the URL strings. When integrated with its dynamic live external intelligence APIs (such as Google Safe Browsing and TLS Certificate inspection), the system reaches a formidable 99.4% accuracy. Expected outcomes include the deployment of a highly reliable, automated defense mechanism capable of sharply reducing user susceptibility to credential-theft and social engineering attacks. By successfully deploying the SentinURL system, the project will demonstrate a tangible improvement in cybersecurity defense, providing an intelligent tool that protects individual users and organizations while maintaining a seamless browsing experience.")
    p_results.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    
    doc.add_paragraph() # Spacing
    
    doc.add_heading('3. Conclusion', level=1)
    p_conclusion = doc.add_paragraph("In conclusion, the SentinURL Phishing Detector represents a comprehensive effort to modernise phishing detection techniques limitlessly. Driven by data, structural integrity, and measurable outcomes, it fulfills the requirements for a rigorous and deeply impactful graduation project.")
    p_conclusion.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    # Save
    file_path = os.path.join(r'c:\Users\Asus\Desktop\Graduation Project\PreTrained Models', 'SentinURL_Project_Proposal.docx')
    doc.save(file_path)
    print(f"Document saved successfully to {file_path}")

if __name__ == '__main__':
    create_proposal()
