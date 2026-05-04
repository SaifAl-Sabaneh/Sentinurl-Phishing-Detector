import sys
from fpdf import FPDF

class SimplePDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.set_text_color(40, 70, 120)
        title = getattr(self, 'doc_title', 'SentinURL Document')
        self.cell(0, 10, title, 0, 0, 'C')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def clean_for_pdf(text):
    # Mapping of common unicode characters to ASCII
    mapping = {
        '\u2014': '-', '\u2013': '-', '\u201c': '"', '\u201d': '"',
        '\u2018': "'", '\u2019': "'", '\u2022': '-', '\u2026': '...'
    }
    for k, v in mapping.items():
        text = text.replace(k, v)
    
    # Final safety: strip all non-Latin-1 characters to avoid FPDF crashes
    return "".join(c for c in text if ord(c) < 256)

def convert(input_file, output_file, title):
    pdf = SimplePDF()
    pdf.doc_title = title
    pdf.add_page()
    pdf.set_font('Helvetica', '', 11)
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for line in lines:
            line = clean_for_pdf(line).strip()
            if not line:
                pdf.ln(5)
                continue
                
            if line.startswith('#'):
                level = line.count('#')
                text = line.replace('#', '').strip()
                pdf.set_font('Helvetica', 'B', 16 - (level * 2))
                pdf.set_text_color(40, 70, 120)
                pdf.multi_cell(0, 10, text)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(2)
            elif line.startswith('###'):
                text = line.replace('###', '').strip()
                pdf.set_font('Helvetica', 'B', 12)
                pdf.multi_cell(0, 10, text)
                pdf.ln(1)
            elif line.startswith('---'):
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(5)
            else:
                pdf.set_font('Helvetica', '', 11)
                pdf.multi_cell(0, 7, line)
                pdf.ln(1)
                
        pdf.output(output_file)
        print(f"Successfully created {output_file}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        # Default for the specific request
        convert('LinkedIn_Post.md', 'SentinURL_LinkedIn_Announcement.pdf', 'SentinURL Project Launch')
    else:
        convert(sys.argv[1], sys.argv[2], sys.argv[3])
