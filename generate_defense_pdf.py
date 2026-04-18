import json
import os
from fpdf import FPDF

class DefensePDF(FPDF):
    def header(self):
        # Set background or title styling if needed
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(40, 70, 120)
        self.cell(0, 15, 'SentinURL Graduation Project Defense Notes', 0, 0, 'C')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_qa(self, question, answer):
        # Question block
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(200, 50, 50)
        self.multi_cell(0, 10, f"Q: {question}")
        self.ln(2)
        
        # Answer block
        self.set_font('Helvetica', '', 11)
        self.set_text_color(0, 0, 0)
        self.multi_cell(0, 7, answer)
        self.ln(10)
        self.draw_separator()

    def draw_separator(self):
        curr_y = self.get_y()
        self.set_draw_color(200, 200, 200)
        self.line(10, curr_y, 200, curr_y)
        self.ln(5)

def generate():
    history_path = 'defense_history.json'
    if not os.path.exists(history_path):
        print("No history file found.")
        return

    with open(history_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    pdf = DefensePDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    for i, item in enumerate(data):
        if i > 0:
            pdf.add_page()
        pdf.add_qa(item['question'], item['answer'])

    pdf.output('SentinURL_Defense_Notes.pdf')
    print("PDF generated successfully: SentinURL_Defense_Notes.pdf")

if __name__ == '__main__':
    generate()
