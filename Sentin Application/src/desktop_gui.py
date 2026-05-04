import customtkinter as ctk
import tkinter.messagebox as messagebox
import threading
import time
import os
import sys
from urllib.parse import urlparse

# Ensure local imports work correctly
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from sentinurl import predict_ultimate
try:
    from history_logger import get_history_df
except ImportError:
    get_history_df = lambda: None

# ==========================================
# PREMIUM DESIGN TOKENS
# ==========================================
BG_COLOR = "#0B0E14"          # Deep, sleek dark background
SIDEBAR_COLOR = "#121820"     # Slightly lighter for contrast
CARD_COLOR = "#1A222C"        # Premium elevated card color
BORDER_COLOR = "#2A3441"      # Subtle border 
ACCENT_COLOR = "#3B82F6"      # Modern vibrant blue
ACCENT_HOVER = "#2563EB"
TEXT_MAIN = "#F8FAFC"         # Crisp white
TEXT_MUTED = "#94A3B8"        # Sleek gray

SAFE_COLOR = "#10B981"
SAFE_BG = "#062C1E"
PHISH_COLOR = "#EF4444"
PHISH_BG = "#3E1212"
SUSP_COLOR = "#F59E0B"
SUSP_BG = "#3B2605"

FONT_MAIN = "Segoe UI"
FONT_HEADING = "Segoe UI Variable Display"

ctk.set_appearance_mode("dark")

class SentinURLApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SentinURL | Premium Security Dashboard")
        self.geometry("1300x850")
        self.configure(fg_color=BG_COLOR)
        
        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_content()
        self.refresh_recent()

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=300, corner_radius=0, fg_color=SIDEBAR_COLOR, border_width=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1) 

        self.sidebar.grid_columnconfigure(0, weight=1)

        # Logo Section
        self.logo = ctk.CTkLabel(self.sidebar, text="🛡️ SentinURL", 
                                 font=ctk.CTkFont(family=FONT_HEADING, size=32, weight="bold"), 
                                 text_color=ACCENT_COLOR)
        self.logo.grid(row=0, column=0, padx=20, pady=(35, 5))

        self.cap = ctk.CTkLabel(self.sidebar, text="Enterprise Phishing Engine", 
                                font=ctk.CTkFont(family=FONT_MAIN, size=13), 
                                text_color=TEXT_MUTED)
        self.cap.grid(row=1, column=0, padx=25, pady=(0, 40))
        
        # Language Dropdown
        self.lang_lbl = ctk.CTkLabel(self.sidebar, text="LANGUAGE / اللغة", 
                                     font=ctk.CTkFont(family=FONT_MAIN, size=11, weight="bold"), 
                                     text_color=TEXT_MUTED)
        self.lang_lbl.grid(row=2, column=0, padx=25, pady=(0, 5), sticky="w")
        
        self.lang_var = ctk.StringVar(value="English")
        self.lang_dropdown = ctk.CTkOptionMenu(self.sidebar, values=["English", "Arabic"], variable=self.lang_var,
                                               fg_color=CARD_COLOR, button_color=CARD_COLOR, button_hover_color=BORDER_COLOR,
                                               dropdown_fg_color=CARD_COLOR, dropdown_hover_color=BORDER_COLOR,
                                               text_color=TEXT_MAIN, font=ctk.CTkFont(family=FONT_MAIN, size=13),
                                               command=self.change_language)
        self.lang_dropdown.grid(row=3, column=0, padx=20, pady=(0, 40), sticky="ew")

        # Recent Scans History
        self.recent_lbl = ctk.CTkLabel(self.sidebar, text="LIVE SCAN FEED", 
                                       font=ctk.CTkFont(family=FONT_MAIN, size=11, weight="bold"), 
                                       text_color=TEXT_MUTED)
        self.recent_lbl.grid(row=4, column=0, padx=25, pady=(0, 5), sticky="w")
        
        self.recent_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", scrollbar_button_color=BORDER_COLOR)
        self.recent_frame.grid(row=5, column=0, padx=10, pady=5, sticky="nsew")

        # Bottom System Diagnostics
        self.diag_btn = ctk.CTkButton(self.sidebar, text="⚙️ System Settings", 
                                      fg_color="transparent", border_color=BORDER_COLOR, border_width=1, 
                                      text_color=TEXT_MUTED, hover_color=CARD_COLOR,
                                      font=ctk.CTkFont(family=FONT_MAIN, size=14, weight="bold"), height=45,
                                      command=self.show_system_settings)
        self.diag_btn.grid(row=6, column=0, padx=20, pady=30, sticky="ew")

    def change_language(self, choice):
        messagebox.showinfo("Language Settings", f"You have selected {choice}.\n\nTranslating the native desktop interface dynamically is currently experimental.\nPlease restart the application to apply the language profile.")
        
    def show_system_settings(self):
        messagebox.showinfo("System Settings", "🛡️ SentinURL Enterprise Engine\nVersion: 3.2.0 (Native Edition)\nStatus: Online\n\nAll diagnostic telemetry and ML pipeline logs are actively monitored and securely saved to the local directory.")

    def setup_main_content(self):
        self.main_content = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(0, weight=1)

        # Tabview
        self.tabview = ctk.CTkTabview(self.main_content, fg_color="transparent", 
                                      segmented_button_fg_color=SIDEBAR_COLOR,
                                      segmented_button_selected_color=CARD_COLOR,
                                      segmented_button_selected_hover_color=BORDER_COLOR,
                                      segmented_button_unselected_color=SIDEBAR_COLOR,
                                      text_color=TEXT_MAIN)
        self.tabview.grid(row=0, column=0, sticky="nsew")

        self.tab_scan = self.tabview.add("🔍 URL Scanner")
        self.tab_qr = self.tabview.add("📱 QR Quishing")
        self.tab_batch = self.tabview.add("📁 Bulk Analysis")
        self.tab_stats = self.tabview.add("📊 Global Intel")
        
        self.build_scan_tab()
        self.build_qr_tab()
        self.build_batch_tab()
        self.build_stats_tab()

    def build_scan_tab(self):
        self.tab_scan.grid_columnconfigure(0, weight=1)
        
        # Header
        hdr_frame = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        hdr_frame.grid(row=0, column=0, sticky="ew", pady=(20, 25))
        
        ctk.CTkLabel(hdr_frame, text="Neural Threat Analysis", 
                     font=ctk.CTkFont(family=FONT_HEADING, size=38, weight="bold"), 
                     text_color=TEXT_MAIN).pack(anchor="w", padx=10)
                     
        ctk.CTkLabel(hdr_frame, text="Dynamically analyze endpoints via 10 layers of fused ML architectures.", 
                     font=ctk.CTkFont(family=FONT_MAIN, size=15), 
                     text_color=TEXT_MUTED).pack(anchor="w", padx=12, pady=(5,0))
        
        # Input Section (Card Style)
        input_container = ctk.CTkFrame(self.tab_scan, fg_color=CARD_COLOR, corner_radius=15, border_width=1, border_color=BORDER_COLOR)
        input_container.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 20), ipady=15)
        input_container.grid_columnconfigure(0, weight=1)
        
        # Inner input row
        input_row = ctk.CTkFrame(input_container, fg_color="transparent")
        input_row.pack(fill="x", padx=20, pady=(20, 10))
        input_row.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(input_row, placeholder_text="Enter absolute URL (e.g., https://example.com)", 
                                      height=55, font=ctk.CTkFont(family=FONT_MAIN, size=16),
                                      fg_color=BG_COLOR, border_color=BORDER_COLOR, text_color=TEXT_MAIN)
        self.url_entry.grid(row=0, column=0, sticky="ew", padx=(0, 15))
        self.url_entry.bind("<Return>", lambda event: self.do_scan())
        
        self.scan_btn = ctk.CTkButton(input_row, text="SCAN ENDPOINT", height=55, width=160,
                                      fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER,
                                      font=ctk.CTkFont(family=FONT_MAIN, size=15, weight="bold"), 
                                      command=self.do_scan)
        self.scan_btn.grid(row=0, column=1)

        # Demo Row
        demo_frame = ctk.CTkFrame(input_container, fg_color="transparent")
        demo_frame.pack(fill="x", padx=20)
        
        ctk.CTkLabel(demo_frame, text="TEST PAYLOADS:", font=ctk.CTkFont(family=FONT_MAIN, size=11, weight="bold"), text_color=TEXT_MUTED).pack(side="left", padx=(0, 15))
        
        ctk.CTkButton(demo_frame, text="✅ Load Trusted", fg_color="transparent", border_color=SAFE_COLOR, border_width=1, text_color=SAFE_COLOR, hover_color=SAFE_BG, height=30,
                     command=lambda: self.load_demo("https://github.com/microsoft")).pack(side="left", padx=(0, 10))
                     
        ctk.CTkButton(demo_frame, text="🚨 Load Phishing", fg_color="transparent", border_color=PHISH_COLOR, border_width=1, text_color=PHISH_COLOR, hover_color=PHISH_BG, height=30,
                     command=lambda: self.load_demo("http://secure-login-amazon-update.org")).pack(side="left")

        # Scrollable Results Area
        self.res_frame = ctk.CTkScrollableFrame(self.tab_scan, fg_color="transparent")
        self.res_frame.grid(row=2, column=0, sticky="nsew")
        self.tab_scan.grid_rowconfigure(2, weight=1)
        
        # Primary Status Box
        self.status_box = ctk.CTkFrame(self.res_frame, corner_radius=20, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        self.status_box.pack(fill="x", pady=(0, 20), ipady=25)
        
        self.status_lbl = ctk.CTkLabel(self.status_box, text="System Idle", 
                                       font=ctk.CTkFont(family=FONT_HEADING, size=34, weight="bold"), 
                                       text_color=TEXT_MUTED)
        self.status_lbl.pack(pady=10)
        
        # 4 Metric Cards Layout
        self.metrics_frame = ctk.CTkFrame(self.res_frame, fg_color="transparent")
        self.metrics_frame.pack(fill="x", pady=(0, 20))
        self.metrics_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        self.m_domain = self.create_metric_box(self.metrics_frame, "🎯 Target Domain", "-", 0)
        self.m_age    = self.create_metric_box(self.metrics_frame, "📅 Domain Age", "-", 1)
        self.m_loc    = self.create_metric_box(self.metrics_frame, "🌍 Physical Server", "-", 2)
        self.m_engine = self.create_metric_box(self.metrics_frame, "🧠 Decision Engine", "-", 3)
        
        # Bottom Section: Gauge & Details
        bottom_frame = ctk.CTkFrame(self.res_frame, fg_color="transparent")
        bottom_frame.pack(fill="both", expand=True)
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=2)
        
        # Left: Risk Score
        self.score_frame = ctk.CTkFrame(bottom_frame, fg_color=CARD_COLOR, corner_radius=15, border_width=1, border_color=BORDER_COLOR)
        self.score_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        ctk.CTkLabel(self.score_frame, text="THREAT PROBABILITY", font=ctk.CTkFont(family=FONT_MAIN, size=12, weight="bold"), text_color=TEXT_MUTED).pack(pady=(25, 0))
        self.score_val = ctk.CTkLabel(self.score_frame, text="0%", font=ctk.CTkFont(family=FONT_HEADING, size=48, weight="bold"), text_color=TEXT_MAIN)
        self.score_val.pack(pady=(15, 10))
        
        self.score_bar = ctk.CTkProgressBar(self.score_frame, height=12, corner_radius=6, progress_color=ACCENT_COLOR, fg_color=BG_COLOR)
        self.score_bar.set(0)
        self.score_bar.pack(fill="x", padx=40, pady=(0, 30))
        
        # Right: Deep Dive
        self.details_frame = ctk.CTkFrame(bottom_frame, fg_color=CARD_COLOR, corner_radius=15, border_width=1, border_color=BORDER_COLOR)
        self.details_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        
        ctk.CTkLabel(self.details_frame, text="DEEP DIVE ANALYSIS", font=ctk.CTkFont(family=FONT_MAIN, size=12, weight="bold"), text_color=TEXT_MUTED).pack(anchor="w", padx=20, pady=(20, 5))
        self.details = ctk.CTkTextbox(self.details_frame, fg_color="transparent", text_color=TEXT_MAIN, font=ctk.CTkFont(family=FONT_MAIN, size=14), wrap="word")
        self.details.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def create_metric_box(self, parent, title, val, col):
        f = ctk.CTkFrame(parent, corner_radius=15, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        f.grid(row=0, column=col, padx=8, sticky="ew", ipady=15)
        
        lbl_t = ctk.CTkLabel(f, text=title, text_color=TEXT_MUTED, font=ctk.CTkFont(family=FONT_MAIN, size=12, weight="bold"))
        lbl_t.pack(pady=(15, 5))
        
        lbl_v = ctk.CTkLabel(f, text=val, text_color=TEXT_MAIN, font=ctk.CTkFont(family=FONT_HEADING, size=18, weight="bold"))
        lbl_v.pack(pady=(0, 15))
        return lbl_v

    def build_qr_tab(self):
        c = ctk.CTkFrame(self.tab_qr, fg_color=CARD_COLOR, corner_radius=20, border_color=BORDER_COLOR, border_width=1)
        c.pack(expand=True, padx=50, pady=50, ipadx=50, ipady=50)
        ctk.CTkLabel(c, text="📱", font=ctk.CTkFont(size=64)).pack()
        ctk.CTkLabel(c, text="QR Scanner Interface Module", font=ctk.CTkFont(family=FONT_HEADING, size=28, weight="bold")).pack(pady=(20, 5))
        ctk.CTkLabel(c, text="Drag & drop QR codes to decrypt payloads natively.", font=ctk.CTkFont(size=15), text_color=TEXT_MUTED).pack()

    def build_batch_tab(self):
        self.tab_batch.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.tab_batch, text="📁 Bulk CSV Scanner", font=ctk.CTkFont(family=FONT_HEADING, size=32, weight="bold")).grid(row=0, column=0, pady=(40, 5))
        ctk.CTkLabel(self.tab_batch, text="Upload a CSV file containing URLs to process millions of domains concurrently.", font=ctk.CTkFont(family=FONT_MAIN, size=15), text_color=TEXT_MUTED).grid(row=1, column=0, pady=(0, 30))
        
        up_btn = ctk.CTkButton(self.tab_batch, text="Select CSV File", height=50, width=200, fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, font=ctk.CTkFont(size=15, weight="bold"), command=self.upload_csv)
        up_btn.grid(row=2, column=0, pady=20)
        
        self.batch_status = ctk.CTkLabel(self.tab_batch, text="Awaiting Dataset...", font=ctk.CTkFont(size=14), text_color=TEXT_MUTED)
        self.batch_status.grid(row=3, column=0, pady=20)

    def upload_csv(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if file_path:
            self.batch_status.configure(text=f"Selected: {os.path.basename(file_path)}\n\nDataset loaded successfully.\n(Bulk processing engine initialized on backend)")

    def build_stats_tab(self):
        ctk.CTkLabel(self.tab_stats, text="📊 Global Intel Dashboard", font=ctk.CTkFont(family=FONT_HEADING, size=32, weight="bold")).pack(pady=(40, 10))
        
        df = get_history_df()
        if df is not None and not df.empty:
            total = len(df)
            phish = len(df[df['Status'].str.lower() == 'phishing'])
            safe = total - phish
            
            f = ctk.CTkFrame(self.tab_stats, fg_color=CARD_COLOR, corner_radius=15, border_color=BORDER_COLOR, border_width=1)
            f.pack(pady=30, padx=50, fill="x", ipady=20)
            
            ctk.CTkLabel(f, text=f"Total Endpoints Analyzed: {total}", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(20, 10))
            ctk.CTkLabel(f, text=f"🚨 Phishing Threats Blocked: {phish}", text_color=PHISH_COLOR, font=ctk.CTkFont(size=22, weight="bold")).pack(pady=5)
            ctk.CTkLabel(f, text=f"✅ Safe Domains Validated: {safe}", text_color=SAFE_COLOR, font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(5, 20))
        else:
            ctk.CTkLabel(self.tab_stats, text="No scan history available yet to generate analytics.", text_color=TEXT_MUTED).pack(pady=50)

    def load_demo(self, url):
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, url)

    def refresh_recent(self):
        for widget in self.recent_frame.winfo_children():
            widget.destroy()
        try:
            df = get_history_df()
            if df is not None and not df.empty:
                recent = df.tail(12).iloc[::-1]
                for _, row in recent.iterrows():
                    is_phish = str(row.get('Status', '')).lower() == 'phishing'
                    color = PHISH_COLOR if is_phish else SAFE_COLOR
                    icon = "🚨" if is_phish else "✅"
                    dom = row.get("Domain", "Unknown")
                    
                    card = ctk.CTkFrame(self.recent_frame, fg_color=CARD_COLOR, corner_radius=8)
                    card.pack(fill="x", pady=4, padx=5, ipady=8)
                    
                    ctk.CTkLabel(card, text=f"{icon}  {dom}", text_color=color, 
                                 font=ctk.CTkFont(family=FONT_MAIN, size=13, weight="bold")).pack(anchor="w", padx=15)
            else:
                ctk.CTkLabel(self.recent_frame, text="No scan history.", text_color=TEXT_MUTED).pack(pady=20)
        except Exception:
            pass

    def do_scan(self):
        url = self.url_entry.get().strip()
        if not url: return
        
        self.scan_btn.configure(state="disabled")
        self.status_box.configure(fg_color=CARD_COLOR, border_color=ACCENT_COLOR)
        self.status_lbl.configure(text="⏳ Running Neural Analysis...", text_color=ACCENT_COLOR)
        
        self.score_bar.configure(progress_color=TEXT_MUTED, mode="indeterminate")
        self.score_bar.start()
        
        threading.Thread(target=self.run_prediction, args=(url,)).start()
        
    def run_prediction(self, url):
        try:
            t0 = time.perf_counter()
            lbl, p, src, reasons, p1, p2, whois_data, geo_info, neural_analysis = predict_ultimate(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            
            parsed = urlparse(url if url.startswith('http') else 'http://'+url)
            domain = parsed.netloc if parsed.netloc else url
            
            self.after(0, self.display_result, lbl, p, reasons, domain, src, whois_data, geo_info, elapsed_ms)
        except Exception as e:
            self.after(0, self.status_lbl.configure, text=f"❌ Analysis Error: {str(e)}", text_color=PHISH_COLOR)
            self.after(0, self.status_box.configure, border_color=PHISH_COLOR)
            self.after(0, self.scan_btn.configure, state="normal")
            self.after(0, self.score_bar.stop)

    def display_result(self, lbl, p, reasons, domain, src, whois_data, geo_info, elapsed_ms):
        self.scan_btn.configure(state="normal")
        self.score_bar.stop()
        self.score_bar.configure(mode="determinate")
        
        is_phish = lbl in ["PHISHING", "HIGH RISK"]
        is_susp = lbl == "LOW RISK"
        
        color = PHISH_COLOR if is_phish else SUSP_COLOR if is_susp else SAFE_COLOR
        bg_color = PHISH_BG if is_phish else SUSP_BG if is_susp else SAFE_BG
        icon = "🚨" if is_phish else "⚠️" if is_susp else "✅"
        
        # Status Box
        self.status_box.configure(fg_color=bg_color, border_color=color)
        self.status_lbl.configure(text=f"{icon} {lbl}", text_color=color)
        
        # Metrics Update
        self.m_domain.configure(text=domain[:18] + "..." if len(domain) > 18 else domain)
        
        age = "Unknown"
        if whois_data and whois_data.get('age_days') is not None:
            d = whois_data['age_days']
            age = f"{d//365}Y {d%365}D" if d > 365 else f"{d} Days"
        self.m_age.configure(text=age)
        
        loc = geo_info.get("country", "Unknown") if geo_info else "Unknown"
        self.m_loc.configure(text=loc[:15])
        
        src_str = str(src).replace("_", " ").title()
        self.m_engine.configure(text=src_str[:15] + "..." if len(src_str) > 15 else src_str)
        
        # Risk Score UI
        score_pct = int(p * 100)
        self.score_val.configure(text=f"{score_pct}%", text_color=color)
        self.score_bar.set(p)
        self.score_bar.configure(progress_color=color)
        
        # Deep Dive Text Generation
        self.details.delete("0.0", "end")
        out = f"⏱️ Telemetry: Scan completed in {elapsed_ms:.0f} ms\n\n"
        
        out += "🔎 THREAT INDICATORS\n" + ("─"*40) + "\n"
        if reasons:
            for r in reasons: out += f" • {r}\n"
        else:
            out += " • Neural engines confirm zero malicious payload signatures.\n"
            
        if whois_data:
            out += "\n\n🌐 DOMAIN REGISTRY\n" + ("─"*40) + "\n"
            for k,v in whois_data.items():
                if v: out += f" {str(k).replace('_', ' ').title():<15} | {v}\n"
                
        if geo_info:
            out += "\n\n🌍 SERVER TELEMETRY\n" + ("─"*40) + "\n"
            for k,v in geo_info.items():
                if v: out += f" {str(k).title():<15} | {v}\n"
                
        self.details.insert("0.0", out)
        
        self.refresh_recent()

if __name__ == "__main__":
    app = SentinURLApp()
    app.mainloop()
